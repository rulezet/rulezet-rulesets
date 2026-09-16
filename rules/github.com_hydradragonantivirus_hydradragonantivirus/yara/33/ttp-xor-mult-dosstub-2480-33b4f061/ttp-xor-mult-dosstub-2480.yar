rule TTP_XOR_MULT_DOSStub_2480 {
  strings:
    $key_2480 = { 70 e8 [2] 04 f0 [2] 43 f2 [2] 04 e3 [2] 4a ef [2] 46 e5 [2] 51 ee [2] 4a a0 [2] 77 }

  condition:
    any of them
}