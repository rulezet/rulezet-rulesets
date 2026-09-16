rule TTP_XOR_MULT_DOSStub_44a4 {
  strings:
    $key_44a4 = { 10 cc [2] 64 d4 [2] 23 d6 [2] 64 c7 [2] 2a cb [2] 26 c1 [2] 31 ca [2] 2a 84 [2] 17 }

  condition:
    any of them
}