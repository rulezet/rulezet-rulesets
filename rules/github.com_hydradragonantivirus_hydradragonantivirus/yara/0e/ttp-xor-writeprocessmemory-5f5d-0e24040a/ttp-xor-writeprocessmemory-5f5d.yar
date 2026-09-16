rule TTP_XOR_WriteProcessMemory_5f5d {
  strings:
    $key_5f5d = { 08 2f [2] 3a 0d [2] 3c 38 [2] 12 38 [2] 2d 24 }

  condition:
    any of them
}