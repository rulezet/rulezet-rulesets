rule TTP_XOR_MULT_DOSStub_aec7 {
  strings:
    $key_aec7 = { fa af [2] 8e b7 [2] c9 b5 [2] 8e a4 [2] c0 a8 [2] cc a2 [2] db a9 [2] c0 e7 [2] fd }

  condition:
    any of them
}