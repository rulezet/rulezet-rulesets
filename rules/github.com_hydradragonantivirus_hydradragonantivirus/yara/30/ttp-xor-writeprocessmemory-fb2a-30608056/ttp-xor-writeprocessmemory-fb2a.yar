rule TTP_XOR_WriteProcessMemory_fb2a {
  strings:
    $key_fb2a = { ac 58 [2] 9e 7a [2] 98 4f [2] b6 4f [2] 89 53 }

  condition:
    any of them
}