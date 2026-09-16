rule TTP_XOR_MULT_DOSStub_d886 {
  strings:
    $key_d886 = { 8c ee [2] f8 f6 [2] bf f4 [2] f8 e5 [2] b6 e9 [2] ba e3 [2] ad e8 [2] b6 a6 [2] 8b }

  condition:
    any of them
}