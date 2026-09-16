rule TTP_XOR_MULT_DOSStub_ca90 {
  strings:
    $key_ca90 = { 9e f8 [2] ea e0 [2] ad e2 [2] ea f3 [2] a4 ff [2] a8 f5 [2] bf fe [2] a4 b0 [2] 99 }

  condition:
    any of them
}