rule TTP_XOR_MULT_DOSStub_1080 {
  strings:
    $key_1080 = { 44 e8 [2] 30 f0 [2] 77 f2 [2] 30 e3 [2] 7e ef [2] 72 e5 [2] 65 ee [2] 7e a0 [2] 43 }

  condition:
    any of them
}