rule TTP_XOR_MULT_DOSStub_fe80 {
  strings:
    $key_fe80 = { aa e8 [2] de f0 [2] 99 f2 [2] de e3 [2] 90 ef [2] 9c e5 [2] 8b ee [2] 90 a0 [2] ad }

  condition:
    any of them
}