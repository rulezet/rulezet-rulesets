rule TTP_XOR_WriteProcessMemory_cdc0 {
  strings:
    $key_cdc0 = { 9a b2 [2] a8 90 [2] ae a5 [2] 80 a5 [2] bf b9 }

  condition:
    any of them
}