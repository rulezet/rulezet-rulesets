rule TTP_XOR_MULT_DOSStub_e106 {
  strings:
    $key_e106 = { b5 6e [2] c1 76 [2] 86 74 [2] c1 65 [2] 8f 69 [2] 83 63 [2] 94 68 [2] 8f 26 [2] b2 }

  condition:
    any of them
}