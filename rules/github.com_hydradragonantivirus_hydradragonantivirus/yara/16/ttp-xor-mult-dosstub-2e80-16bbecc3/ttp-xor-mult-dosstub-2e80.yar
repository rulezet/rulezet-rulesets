rule TTP_XOR_MULT_DOSStub_2e80 {
  strings:
    $key_2e80 = { 7a e8 [2] 0e f0 [2] 49 f2 [2] 0e e3 [2] 40 ef [2] 4c e5 [2] 5b ee [2] 40 a0 [2] 7d }

  condition:
    any of them
}