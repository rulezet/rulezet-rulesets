rule TTP_XOR_MULT_DOSStub_3db3 {
  strings:
    $key_3db3 = { 69 db [2] 1d c3 [2] 5a c1 [2] 1d d0 [2] 53 dc [2] 5f d6 [2] 48 dd [2] 53 93 [2] 6e }

  condition:
    any of them
}