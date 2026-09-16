rule TTP_XOR_MULT_DOSStub_82c2 {
  strings:
    $key_82c2 = { d6 aa [2] a2 b2 [2] e5 b0 [2] a2 a1 [2] ec ad [2] e0 a7 [2] f7 ac [2] ec e2 [2] d1 }

  condition:
    any of them
}