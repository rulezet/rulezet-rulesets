rule TTP_XOR_MULT_DOSStub_34a4 {
  strings:
    $key_34a4 = { 60 cc [2] 14 d4 [2] 53 d6 [2] 14 c7 [2] 5a cb [2] 56 c1 [2] 41 ca [2] 5a 84 [2] 67 }

  condition:
    any of them
}