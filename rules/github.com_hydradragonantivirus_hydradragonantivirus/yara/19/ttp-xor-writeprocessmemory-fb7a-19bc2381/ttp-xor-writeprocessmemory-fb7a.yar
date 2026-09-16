rule TTP_XOR_WriteProcessMemory_fb7a {
  strings:
    $key_fb7a = { ac 08 [2] 9e 2a [2] 98 1f [2] b6 1f [2] 89 03 }

  condition:
    any of them
}