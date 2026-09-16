rule TTP_XOR_MULT_DOSStub_ca9f {
  strings:
    $key_ca9f = { 9e f7 [2] ea ef [2] ad ed [2] ea fc [2] a4 f0 [2] a8 fa [2] bf f1 [2] a4 bf [2] 99 }

  condition:
    any of them
}