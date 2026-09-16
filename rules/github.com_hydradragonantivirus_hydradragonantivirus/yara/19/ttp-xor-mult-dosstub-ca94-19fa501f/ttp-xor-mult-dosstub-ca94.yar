rule TTP_XOR_MULT_DOSStub_ca94 {
  strings:
    $key_ca94 = { 9e fc [2] ea e4 [2] ad e6 [2] ea f7 [2] a4 fb [2] a8 f1 [2] bf fa [2] a4 b4 [2] 99 }

  condition:
    any of them
}