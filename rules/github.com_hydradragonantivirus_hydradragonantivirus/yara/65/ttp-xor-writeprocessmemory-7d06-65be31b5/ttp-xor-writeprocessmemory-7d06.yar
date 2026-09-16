rule TTP_XOR_WriteProcessMemory_7d06 {
  strings:
    $key_7d06 = { 2a 74 [2] 18 56 [2] 1e 63 [2] 30 63 [2] 0f 7f }

  condition:
    any of them
}