rule TTP_XOR_MULT_DOSStub_2380 {
  strings:
    $key_2380 = { 77 e8 [2] 03 f0 [2] 44 f2 [2] 03 e3 [2] 4d ef [2] 41 e5 [2] 56 ee [2] 4d a0 [2] 70 }

  condition:
    any of them
}