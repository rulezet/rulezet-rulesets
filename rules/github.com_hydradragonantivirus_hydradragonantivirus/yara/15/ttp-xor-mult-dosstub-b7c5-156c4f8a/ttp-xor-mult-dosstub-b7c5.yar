rule TTP_XOR_MULT_DOSStub_b7c5 {
  strings:
    $key_b7c5 = { e3 ad [2] 97 b5 [2] d0 b7 [2] 97 a6 [2] d9 aa [2] d5 a0 [2] c2 ab [2] d9 e5 [2] e4 }

  condition:
    any of them
}