rule TTP_XOR_WriteProcessMemory_cdc5 {
  strings:
    $key_cdc5 = { 9a b7 [2] a8 95 [2] ae a0 [2] 80 a0 [2] bf bc }

  condition:
    any of them
}