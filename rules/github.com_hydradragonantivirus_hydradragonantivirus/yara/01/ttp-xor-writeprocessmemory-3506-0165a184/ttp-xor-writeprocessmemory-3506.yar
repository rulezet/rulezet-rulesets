rule TTP_XOR_WriteProcessMemory_3506 {
  strings:
    $key_3506 = { 62 74 [2] 50 56 [2] 56 63 [2] 78 63 [2] 47 7f }

  condition:
    any of them
}