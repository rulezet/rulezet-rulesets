rule TTP_XOR_MULT_DOSStub_d9a4 {
  strings:
    $key_d9a4 = { 8d cc [2] f9 d4 [2] be d6 [2] f9 c7 [2] b7 cb [2] bb c1 [2] ac ca [2] b7 84 [2] 8a }

  condition:
    any of them
}