rule TTP_XOR_WriteProcessMemory_5f33 {
  strings:
    $key_5f33 = { 08 41 [2] 3a 63 [2] 3c 56 [2] 12 56 [2] 2d 4a }

  condition:
    any of them
}