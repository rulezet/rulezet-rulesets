rule TTP_XOR_MULT_DOSStub_c083 {
  strings:
    $key_c083 = { 94 eb [2] e0 f3 [2] a7 f1 [2] e0 e0 [2] ae ec [2] a2 e6 [2] b5 ed [2] ae a3 [2] 93 }

  condition:
    any of them
}