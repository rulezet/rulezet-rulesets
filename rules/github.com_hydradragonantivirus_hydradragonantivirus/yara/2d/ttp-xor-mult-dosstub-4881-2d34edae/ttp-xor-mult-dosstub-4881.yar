rule TTP_XOR_MULT_DOSStub_4881 {
  strings:
    $key_4881 = { 1c e9 [2] 68 f1 [2] 2f f3 [2] 68 e2 [2] 26 ee [2] 2a e4 [2] 3d ef [2] 26 a1 [2] 1b }

  condition:
    any of them
}