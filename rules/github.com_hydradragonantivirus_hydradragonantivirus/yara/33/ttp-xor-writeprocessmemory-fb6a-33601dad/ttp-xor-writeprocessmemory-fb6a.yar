rule TTP_XOR_WriteProcessMemory_fb6a {
  strings:
    $key_fb6a = { ac 18 [2] 9e 3a [2] 98 0f [2] b6 0f [2] 89 13 }

  condition:
    any of them
}