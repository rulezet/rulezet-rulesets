rule TTP_XOR_WriteProcessMemory_5f4d {
  strings:
    $key_5f4d = { 08 3f [2] 3a 1d [2] 3c 28 [2] 12 28 [2] 2d 34 }

  condition:
    any of them
}