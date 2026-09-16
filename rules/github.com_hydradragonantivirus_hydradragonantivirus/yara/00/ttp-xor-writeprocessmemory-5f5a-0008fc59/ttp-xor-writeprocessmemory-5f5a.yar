rule TTP_XOR_WriteProcessMemory_5f5a {
  strings:
    $key_5f5a = { 08 28 [2] 3a 0a [2] 3c 3f [2] 12 3f [2] 2d 23 }

  condition:
    any of them
}