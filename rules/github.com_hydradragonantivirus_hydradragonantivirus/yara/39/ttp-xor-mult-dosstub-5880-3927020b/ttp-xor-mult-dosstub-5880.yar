rule TTP_XOR_MULT_DOSStub_5880 {
  strings:
    $key_5880 = { 0c e8 [2] 78 f0 [2] 3f f2 [2] 78 e3 [2] 36 ef [2] 3a e5 [2] 2d ee [2] 36 a0 [2] 0b }

  condition:
    any of them
}