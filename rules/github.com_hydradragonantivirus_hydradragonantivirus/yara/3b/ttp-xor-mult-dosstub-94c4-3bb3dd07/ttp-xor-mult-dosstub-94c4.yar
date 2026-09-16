rule TTP_XOR_MULT_DOSStub_94c4 {
  strings:
    $key_94c4 = { c0 ac [2] b4 b4 [2] f3 b6 [2] b4 a7 [2] fa ab [2] f6 a1 [2] e1 aa [2] fa e4 [2] c7 }

  condition:
    any of them
}