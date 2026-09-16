rule TTP_XOR_MULT_DOSStub_cc88 {
  strings:
    $key_cc88 = { 98 e0 [2] ec f8 [2] ab fa [2] ec eb [2] a2 e7 [2] ae ed [2] b9 e6 [2] a2 a8 [2] 9f }

  condition:
    any of them
}