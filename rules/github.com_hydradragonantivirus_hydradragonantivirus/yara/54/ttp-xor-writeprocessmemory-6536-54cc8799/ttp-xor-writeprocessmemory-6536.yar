rule TTP_XOR_WriteProcessMemory_6536 {
  strings:
    $key_6536 = { 32 44 [2] 00 66 [2] 06 53 [2] 28 53 [2] 17 4f }

  condition:
    any of them
}