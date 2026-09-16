rule TTP_XOR_MULT_DOSStub_dad7 {
  strings:
    $key_dad7 = { 8e bf [2] fa a7 [2] bd a5 [2] fa b4 [2] b4 b8 [2] b8 b2 [2] af b9 [2] b4 f7 [2] 89 }

  condition:
    any of them
}