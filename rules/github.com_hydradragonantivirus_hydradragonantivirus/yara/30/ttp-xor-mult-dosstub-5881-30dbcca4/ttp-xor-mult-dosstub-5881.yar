rule TTP_XOR_MULT_DOSStub_5881 {
  strings:
    $key_5881 = { 0c e9 [2] 78 f1 [2] 3f f3 [2] 78 e2 [2] 36 ee [2] 3a e4 [2] 2d ef [2] 36 a1 [2] 0b }

  condition:
    any of them
}