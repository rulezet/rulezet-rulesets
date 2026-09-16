rule TTP_XOR_MULT_DOSStub_e176 {
  strings:
    $key_e176 = { b5 1e [2] c1 06 [2] 86 04 [2] c1 15 [2] 8f 19 [2] 83 13 [2] 94 18 [2] 8f 56 [2] b2 }

  condition:
    any of them
}