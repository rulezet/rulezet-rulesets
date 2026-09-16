rule TTP_XOR_MULT_DOSStub_1e80 {
  strings:
    $key_1e80 = { 4a e8 [2] 3e f0 [2] 79 f2 [2] 3e e3 [2] 70 ef [2] 7c e5 [2] 6b ee [2] 70 a0 [2] 4d }

  condition:
    any of them
}