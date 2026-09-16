rule TTP_XOR_WriteProcessMemory_5536 {
  strings:
    $key_5536 = { 02 44 [2] 30 66 [2] 36 53 [2] 18 53 [2] 27 4f }

  condition:
    any of them
}