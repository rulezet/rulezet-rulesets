rule TTP_XOR_MULT_DOSStub_ca9a {
  strings:
    $key_ca9a = { 9e f2 [2] ea ea [2] ad e8 [2] ea f9 [2] a4 f5 [2] a8 ff [2] bf f4 [2] a4 ba [2] 99 }

  condition:
    any of them
}