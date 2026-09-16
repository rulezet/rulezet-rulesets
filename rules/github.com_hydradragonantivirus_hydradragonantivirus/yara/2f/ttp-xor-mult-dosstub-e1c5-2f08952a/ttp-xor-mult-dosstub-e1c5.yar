rule TTP_XOR_MULT_DOSStub_e1c5 {
  strings:
    $key_e1c5 = { b5 ad [2] c1 b5 [2] 86 b7 [2] c1 a6 [2] 8f aa [2] 83 a0 [2] 94 ab [2] 8f e5 [2] b2 }

  condition:
    any of them
}