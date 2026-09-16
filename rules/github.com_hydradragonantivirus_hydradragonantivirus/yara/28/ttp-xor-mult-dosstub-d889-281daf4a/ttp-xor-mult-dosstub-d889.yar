rule TTP_XOR_MULT_DOSStub_d889 {
  strings:
    $key_d889 = { 8c e1 [2] f8 f9 [2] bf fb [2] f8 ea [2] b6 e6 [2] ba ec [2] ad e7 [2] b6 a9 [2] 8b }

  condition:
    any of them
}