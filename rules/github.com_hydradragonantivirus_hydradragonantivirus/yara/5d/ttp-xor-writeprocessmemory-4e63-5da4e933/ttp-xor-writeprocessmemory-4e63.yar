rule TTP_XOR_WriteProcessMemory_4e63 {
  strings:
    $key_4e63 = { 19 11 [2] 2b 33 [2] 2d 06 [2] 03 06 [2] 3c 1a }

  condition:
    any of them
}