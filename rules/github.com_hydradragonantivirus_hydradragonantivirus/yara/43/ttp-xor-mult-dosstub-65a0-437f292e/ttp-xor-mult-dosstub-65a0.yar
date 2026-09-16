rule TTP_XOR_MULT_DOSStub_65a0 {
  strings:
    $key_65a0 = { 31 c8 [2] 45 d0 [2] 02 d2 [2] 45 c3 [2] 0b cf [2] 07 c5 [2] 10 ce [2] 0b 80 [2] 36 }

  condition:
    any of them
}