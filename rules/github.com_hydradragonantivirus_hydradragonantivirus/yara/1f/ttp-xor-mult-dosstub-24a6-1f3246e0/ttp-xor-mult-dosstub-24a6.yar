rule TTP_XOR_MULT_DOSStub_24a6 {
  strings:
    $key_24a6 = { 70 ce [2] 04 d6 [2] 43 d4 [2] 04 c5 [2] 4a c9 [2] 46 c3 [2] 51 c8 [2] 4a 86 [2] 77 }

  condition:
    any of them
}