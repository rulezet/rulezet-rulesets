rule TTP_XOR_WriteProcessMemory_6421 {
  strings:
    $key_6421 = { 33 53 [2] 01 71 [2] 07 44 [2] 29 44 [2] 16 58 }

  condition:
    any of them
}