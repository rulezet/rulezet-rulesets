rule TTP_XOR_MULT_DOSStub_e7c5 {
  strings:
    $key_e7c5 = { b3 ad [2] c7 b5 [2] 80 b7 [2] c7 a6 [2] 89 aa [2] 85 a0 [2] 92 ab [2] 89 e5 [2] b4 }

  condition:
    any of them
}