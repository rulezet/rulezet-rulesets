rule TTP_XOR_MULT_DOSStub_24a4 {
  strings:
    $key_24a4 = { 70 cc [2] 04 d4 [2] 43 d6 [2] 04 c7 [2] 4a cb [2] 46 c1 [2] 51 ca [2] 4a 84 [2] 77 }

  condition:
    any of them
}