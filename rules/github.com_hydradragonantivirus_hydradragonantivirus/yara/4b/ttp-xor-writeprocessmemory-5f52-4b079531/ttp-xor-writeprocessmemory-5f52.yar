rule TTP_XOR_WriteProcessMemory_5f52 {
  strings:
    $key_5f52 = { 08 20 [2] 3a 02 [2] 3c 37 [2] 12 37 [2] 2d 2b }

  condition:
    any of them
}