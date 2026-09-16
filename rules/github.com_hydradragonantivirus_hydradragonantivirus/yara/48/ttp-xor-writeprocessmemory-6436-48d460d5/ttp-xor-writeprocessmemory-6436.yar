rule TTP_XOR_WriteProcessMemory_6436 {
  strings:
    $key_6436 = { 33 44 [2] 01 66 [2] 07 53 [2] 29 53 [2] 16 4f }

  condition:
    any of them
}