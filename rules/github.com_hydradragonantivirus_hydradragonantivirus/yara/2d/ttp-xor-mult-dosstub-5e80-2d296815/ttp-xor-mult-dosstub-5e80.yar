rule TTP_XOR_MULT_DOSStub_5e80 {
  strings:
    $key_5e80 = { 0a e8 [2] 7e f0 [2] 39 f2 [2] 7e e3 [2] 30 ef [2] 3c e5 [2] 2b ee [2] 30 a0 [2] 0d }

  condition:
    any of them
}