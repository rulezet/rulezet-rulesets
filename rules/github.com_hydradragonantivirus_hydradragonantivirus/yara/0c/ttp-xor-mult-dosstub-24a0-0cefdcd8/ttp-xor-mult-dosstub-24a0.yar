rule TTP_XOR_MULT_DOSStub_24a0 {
  strings:
    $key_24a0 = { 70 c8 [2] 04 d0 [2] 43 d2 [2] 04 c3 [2] 4a cf [2] 46 c5 [2] 51 ce [2] 4a 80 [2] 77 }

  condition:
    any of them
}