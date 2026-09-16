rule TTP_XOR_MULT_DOSStub_3880 {
  strings:
    $key_3880 = { 6c e8 [2] 18 f0 [2] 5f f2 [2] 18 e3 [2] 56 ef [2] 5a e5 [2] 4d ee [2] 56 a0 [2] 6b }

  condition:
    any of them
}