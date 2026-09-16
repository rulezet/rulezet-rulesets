rule TTP_XOR_WriteProcessMemory_2506 {
  strings:
    $key_2506 = { 72 74 [2] 40 56 [2] 46 63 [2] 68 63 [2] 57 7f }

  condition:
    any of them
}