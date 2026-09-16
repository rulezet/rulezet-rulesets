rule TTP_XOR_WriteProcessMemory_1426 {
  strings:
    $key_1426 = { 43 54 [2] 71 76 [2] 77 43 [2] 59 43 [2] 66 5f }

  condition:
    any of them
}