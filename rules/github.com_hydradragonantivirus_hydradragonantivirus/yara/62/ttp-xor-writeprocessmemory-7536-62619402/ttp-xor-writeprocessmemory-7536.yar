rule TTP_XOR_WriteProcessMemory_7536 {
  strings:
    $key_7536 = { 22 44 [2] 10 66 [2] 16 53 [2] 38 53 [2] 07 4f }

  condition:
    any of them
}