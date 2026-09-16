rule TTP_XOR_WriteProcessMemory_f661 {
  strings:
    $key_f661 = { a1 13 [2] 93 31 [2] 95 04 [2] bb 04 [2] 84 18 }

  condition:
    any of them
}