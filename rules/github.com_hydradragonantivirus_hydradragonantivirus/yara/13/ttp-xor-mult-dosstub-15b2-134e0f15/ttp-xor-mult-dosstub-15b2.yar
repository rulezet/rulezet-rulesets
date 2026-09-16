rule TTP_XOR_MULT_DOSStub_15b2 {
  strings:
    $key_15b2 = { 41 da [2] 35 c2 [2] 72 c0 [2] 35 d1 [2] 7b dd [2] 77 d7 [2] 60 dc [2] 7b 92 [2] 46 }

  condition:
    any of them
}