rule TTP_XOR_MULT_DOSStub_7fb5 {
  strings:
    $key_7fb5 = { 2b dd [2] 5f c5 [2] 18 c7 [2] 5f d6 [2] 11 da [2] 1d d0 [2] 0a db [2] 11 95 [2] 2c }

  condition:
    any of them
}