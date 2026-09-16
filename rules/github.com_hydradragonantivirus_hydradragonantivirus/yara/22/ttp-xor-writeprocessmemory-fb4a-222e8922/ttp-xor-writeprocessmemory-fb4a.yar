rule TTP_XOR_WriteProcessMemory_fb4a {
  strings:
    $key_fb4a = { ac 38 [2] 9e 1a [2] 98 2f [2] b6 2f [2] 89 33 }

  condition:
    any of them
}