rule TTP_XOR_MULT_DOSStub_ca93 {
  strings:
    $key_ca93 = { 9e fb [2] ea e3 [2] ad e1 [2] ea f0 [2] a4 fc [2] a8 f6 [2] bf fd [2] a4 b3 [2] 99 }

  condition:
    any of them
}