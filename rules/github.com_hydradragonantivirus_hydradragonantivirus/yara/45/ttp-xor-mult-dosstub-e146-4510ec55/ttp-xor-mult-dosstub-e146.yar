rule TTP_XOR_MULT_DOSStub_e146 {
  strings:
    $key_e146 = { b5 2e [2] c1 36 [2] 86 34 [2] c1 25 [2] 8f 29 [2] 83 23 [2] 94 28 [2] 8f 66 [2] b2 }

  condition:
    any of them
}