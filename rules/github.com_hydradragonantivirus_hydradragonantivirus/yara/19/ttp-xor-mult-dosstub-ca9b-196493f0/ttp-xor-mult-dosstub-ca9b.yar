rule TTP_XOR_MULT_DOSStub_ca9b {
  strings:
    $key_ca9b = { 9e f3 [2] ea eb [2] ad e9 [2] ea f8 [2] a4 f4 [2] a8 fe [2] bf f5 [2] a4 bb [2] 99 }

  condition:
    any of them
}