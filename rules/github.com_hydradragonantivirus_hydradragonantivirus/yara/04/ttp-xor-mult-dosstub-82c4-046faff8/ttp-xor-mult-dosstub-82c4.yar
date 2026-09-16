rule TTP_XOR_MULT_DOSStub_82c4 {
  strings:
    $key_82c4 = { d6 ac [2] a2 b4 [2] e5 b6 [2] a2 a7 [2] ec ab [2] e0 a1 [2] f7 aa [2] ec e4 [2] d1 }

  condition:
    any of them
}