rule TTP_XOR_MULT_DOSStub_e0c5 {
  strings:
    $key_e0c5 = { b4 ad [2] c0 b5 [2] 87 b7 [2] c0 a6 [2] 8e aa [2] 82 a0 [2] 95 ab [2] 8e e5 [2] b3 }

  condition:
    any of them
}