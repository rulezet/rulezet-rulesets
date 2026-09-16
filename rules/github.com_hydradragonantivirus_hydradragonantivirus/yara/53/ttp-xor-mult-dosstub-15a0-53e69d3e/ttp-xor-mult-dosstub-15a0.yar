rule TTP_XOR_MULT_DOSStub_15a0 {
  strings:
    $key_15a0 = { 41 c8 [2] 35 d0 [2] 72 d2 [2] 35 c3 [2] 7b cf [2] 77 c5 [2] 60 ce [2] 7b 80 [2] 46 }

  condition:
    any of them
}