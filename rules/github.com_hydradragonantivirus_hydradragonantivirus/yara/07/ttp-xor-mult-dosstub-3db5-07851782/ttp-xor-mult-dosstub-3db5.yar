rule TTP_XOR_MULT_DOSStub_3db5 {
  strings:
    $key_3db5 = { 69 dd [2] 1d c5 [2] 5a c7 [2] 1d d6 [2] 53 da [2] 5f d0 [2] 48 db [2] 53 95 [2] 6e }

  condition:
    any of them
}