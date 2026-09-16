rule TTP_XOR_WriteProcessMemory_cdc3 {
  strings:
    $key_cdc3 = { 9a b1 [2] a8 93 [2] ae a6 [2] 80 a6 [2] bf ba }

  condition:
    any of them
}