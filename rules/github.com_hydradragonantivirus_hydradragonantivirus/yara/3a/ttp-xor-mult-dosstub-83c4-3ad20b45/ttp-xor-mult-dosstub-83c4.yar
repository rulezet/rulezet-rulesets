rule TTP_XOR_MULT_DOSStub_83c4 {
  strings:
    $key_83c4 = { d7 ac [2] a3 b4 [2] e4 b6 [2] a3 a7 [2] ed ab [2] e1 a1 [2] f6 aa [2] ed e4 [2] d0 }

  condition:
    any of them
}