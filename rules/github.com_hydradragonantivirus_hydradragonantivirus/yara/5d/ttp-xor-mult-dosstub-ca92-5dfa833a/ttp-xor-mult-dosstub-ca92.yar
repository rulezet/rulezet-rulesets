rule TTP_XOR_MULT_DOSStub_ca92 {
  strings:
    $key_ca92 = { 9e fa [2] ea e2 [2] ad e0 [2] ea f1 [2] a4 fd [2] a8 f7 [2] bf fc [2] a4 b2 [2] 99 }

  condition:
    any of them
}