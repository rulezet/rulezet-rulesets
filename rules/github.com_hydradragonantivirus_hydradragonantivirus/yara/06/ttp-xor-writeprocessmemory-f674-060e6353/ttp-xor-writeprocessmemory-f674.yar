rule TTP_XOR_WriteProcessMemory_f674 {
  strings:
    $key_f674 = { a1 06 [2] 93 24 [2] 95 11 [2] bb 11 [2] 84 0d }

  condition:
    any of them
}