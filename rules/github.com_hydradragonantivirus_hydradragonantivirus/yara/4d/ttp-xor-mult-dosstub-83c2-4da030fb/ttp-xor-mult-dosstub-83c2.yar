rule TTP_XOR_MULT_DOSStub_83c2 {
  strings:
    $key_83c2 = { d7 aa [2] a3 b2 [2] e4 b0 [2] a3 a1 [2] ed ad [2] e1 a7 [2] f6 ac [2] ed e2 [2] d0 }

  condition:
    any of them
}