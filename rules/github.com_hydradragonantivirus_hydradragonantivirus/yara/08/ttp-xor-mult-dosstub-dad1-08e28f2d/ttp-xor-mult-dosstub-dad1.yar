rule TTP_XOR_MULT_DOSStub_dad1 {
  strings:
    $key_dad1 = { 8e b9 [2] fa a1 [2] bd a3 [2] fa b2 [2] b4 be [2] b8 b4 [2] af bf [2] b4 f1 [2] 89 }

  condition:
    any of them
}