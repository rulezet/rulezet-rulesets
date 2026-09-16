rule TTP_XOR_MULT_DOSStub_94c9 {
  strings:
    $key_94c9 = { c0 a1 [2] b4 b9 [2] f3 bb [2] b4 aa [2] fa a6 [2] f6 ac [2] e1 a7 [2] fa e9 [2] c7 }

  condition:
    any of them
}