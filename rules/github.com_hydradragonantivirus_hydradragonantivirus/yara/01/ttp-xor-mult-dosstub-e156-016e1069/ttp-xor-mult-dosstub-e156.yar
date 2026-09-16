rule TTP_XOR_MULT_DOSStub_e156 {
  strings:
    $key_e156 = { b5 3e [2] c1 26 [2] 86 24 [2] c1 35 [2] 8f 39 [2] 83 33 [2] 94 38 [2] 8f 76 [2] b2 }

  condition:
    any of them
}