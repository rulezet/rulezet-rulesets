rule TTP_XOR_MULT_DOSStub_0880 {
  strings:
    $key_0880 = { 5c e8 [2] 28 f0 [2] 6f f2 [2] 28 e3 [2] 66 ef [2] 6a e5 [2] 7d ee [2] 66 a0 [2] 5b }

  condition:
    any of them
}