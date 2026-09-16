rule TTP_XOR_MULT_DOSStub_1380 {
  strings:
    $key_1380 = { 47 e8 [2] 33 f0 [2] 74 f2 [2] 33 e3 [2] 7d ef [2] 71 e5 [2] 66 ee [2] 7d a0 [2] 40 }

  condition:
    any of them
}