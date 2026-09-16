rule TTP_XOR_MULT_DOSStub_f1c5 {
  strings:
    $key_f1c5 = { a5 ad [2] d1 b5 [2] 96 b7 [2] d1 a6 [2] 9f aa [2] 93 a0 [2] 84 ab [2] 9f e5 [2] a2 }

  condition:
    any of them
}