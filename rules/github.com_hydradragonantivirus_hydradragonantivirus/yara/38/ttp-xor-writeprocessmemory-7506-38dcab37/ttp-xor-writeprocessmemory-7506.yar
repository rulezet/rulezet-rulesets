rule TTP_XOR_WriteProcessMemory_7506 {
  strings:
    $key_7506 = { 22 74 [2] 10 56 [2] 16 63 [2] 38 63 [2] 07 7f }

  condition:
    any of them
}