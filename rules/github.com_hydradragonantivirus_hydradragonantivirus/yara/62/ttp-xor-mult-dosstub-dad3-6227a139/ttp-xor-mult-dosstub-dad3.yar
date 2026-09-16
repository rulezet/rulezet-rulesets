rule TTP_XOR_MULT_DOSStub_dad3 {
  strings:
    $key_dad3 = { 8e bb [2] fa a3 [2] bd a1 [2] fa b0 [2] b4 bc [2] b8 b6 [2] af bd [2] b4 f3 [2] 89 }

  condition:
    any of them
}