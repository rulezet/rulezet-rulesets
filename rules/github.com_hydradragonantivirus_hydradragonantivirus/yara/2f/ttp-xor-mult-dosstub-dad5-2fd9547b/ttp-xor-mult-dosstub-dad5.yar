rule TTP_XOR_MULT_DOSStub_dad5 {
  strings:
    $key_dad5 = { 8e bd [2] fa a5 [2] bd a7 [2] fa b6 [2] b4 ba [2] b8 b0 [2] af bb [2] b4 f5 [2] 89 }

  condition:
    any of them
}