rule TTP_XOR_MULT_DOSStub_0e80 {
  strings:
    $key_0e80 = { 5a e8 [2] 2e f0 [2] 69 f2 [2] 2e e3 [2] 60 ef [2] 6c e5 [2] 7b ee [2] 60 a0 [2] 5d }

  condition:
    any of them
}