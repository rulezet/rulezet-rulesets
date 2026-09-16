rule TTP_XOR_MULT_DOSStub_1881 {
  strings:
    $key_1881 = { 4c e9 [2] 38 f1 [2] 7f f3 [2] 38 e2 [2] 76 ee [2] 7a e4 [2] 6d ef [2] 76 a1 [2] 4b }

  condition:
    any of them
}