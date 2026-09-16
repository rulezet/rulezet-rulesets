rule TTP_XOR_MULT_DOSStub_0db4 {
  strings:
    $key_0db4 = { 59 dc [2] 2d c4 [2] 6a c6 [2] 2d d7 [2] 63 db [2] 6f d1 [2] 78 da [2] 63 94 [2] 5e }

  condition:
    any of them
}