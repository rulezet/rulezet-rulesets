rule TTP_XOR_WriteProcessMemory_f664 {
  strings:
    $key_f664 = { a1 16 [2] 93 34 [2] 95 01 [2] bb 01 [2] 84 1d }

  condition:
    any of them
}