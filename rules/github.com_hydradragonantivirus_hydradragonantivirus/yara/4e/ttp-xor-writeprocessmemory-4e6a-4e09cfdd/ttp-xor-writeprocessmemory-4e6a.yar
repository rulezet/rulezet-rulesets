rule TTP_XOR_WriteProcessMemory_4e6a {
  strings:
    $key_4e6a = { 19 18 [2] 2b 3a [2] 2d 0f [2] 03 0f [2] 3c 13 }

  condition:
    any of them
}