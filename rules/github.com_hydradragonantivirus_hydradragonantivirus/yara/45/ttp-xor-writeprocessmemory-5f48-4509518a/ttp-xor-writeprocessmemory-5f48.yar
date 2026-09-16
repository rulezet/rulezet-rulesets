rule TTP_XOR_WriteProcessMemory_5f48 {
  strings:
    $key_5f48 = { 08 3a [2] 3a 18 [2] 3c 2d [2] 12 2d [2] 2d 31 }

  condition:
    any of them
}