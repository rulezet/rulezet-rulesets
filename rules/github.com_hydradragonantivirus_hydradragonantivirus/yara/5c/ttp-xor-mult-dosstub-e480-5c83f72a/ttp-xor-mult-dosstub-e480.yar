rule TTP_XOR_MULT_DOSStub_e480 {
  strings:
    $key_e480 = { b0 e8 [2] c4 f0 [2] 83 f2 [2] c4 e3 [2] 8a ef [2] 86 e5 [2] 91 ee [2] 8a a0 [2] b7 }

  condition:
    any of them
}