rule TTP_XOR_MULT_DOSStub_dad2 {
  strings:
    $key_dad2 = { 8e ba [2] fa a2 [2] bd a0 [2] fa b1 [2] b4 bd [2] b8 b7 [2] af bc [2] b4 f2 [2] 89 }

  condition:
    any of them
}