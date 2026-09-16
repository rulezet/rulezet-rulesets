rule TTP_XOR_MULT_DOSStub_dad6 {
  strings:
    $key_dad6 = { 8e be [2] fa a6 [2] bd a4 [2] fa b5 [2] b4 b9 [2] b8 b3 [2] af b8 [2] b4 f6 [2] 89 }

  condition:
    any of them
}