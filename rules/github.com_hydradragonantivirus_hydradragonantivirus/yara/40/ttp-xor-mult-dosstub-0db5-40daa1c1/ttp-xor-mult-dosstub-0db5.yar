rule TTP_XOR_MULT_DOSStub_0db5 {
  strings:
    $key_0db5 = { 59 dd [2] 2d c5 [2] 6a c7 [2] 2d d6 [2] 63 da [2] 6f d0 [2] 78 db [2] 63 95 [2] 5e }

  condition:
    any of them
}