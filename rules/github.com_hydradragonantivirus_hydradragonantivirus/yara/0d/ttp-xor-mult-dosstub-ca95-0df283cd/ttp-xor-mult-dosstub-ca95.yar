rule TTP_XOR_MULT_DOSStub_ca95 {
  strings:
    $key_ca95 = { 9e fd [2] ea e5 [2] ad e7 [2] ea f6 [2] a4 fa [2] a8 f0 [2] bf fb [2] a4 b5 [2] 99 }

  condition:
    any of them
}