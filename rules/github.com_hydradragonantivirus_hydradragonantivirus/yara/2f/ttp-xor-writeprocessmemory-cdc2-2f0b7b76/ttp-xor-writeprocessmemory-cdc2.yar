rule TTP_XOR_WriteProcessMemory_cdc2 {
  strings:
    $key_cdc2 = { 9a b0 [2] a8 92 [2] ae a7 [2] 80 a7 [2] bf bb }

  condition:
    any of them
}