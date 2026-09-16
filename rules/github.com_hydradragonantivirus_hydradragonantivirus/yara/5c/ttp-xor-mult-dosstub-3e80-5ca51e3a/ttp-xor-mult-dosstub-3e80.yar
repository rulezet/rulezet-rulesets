rule TTP_XOR_MULT_DOSStub_3e80 {
  strings:
    $key_3e80 = { 6a e8 [2] 1e f0 [2] 59 f2 [2] 1e e3 [2] 50 ef [2] 5c e5 [2] 4b ee [2] 50 a0 [2] 6d }

  condition:
    any of them
}