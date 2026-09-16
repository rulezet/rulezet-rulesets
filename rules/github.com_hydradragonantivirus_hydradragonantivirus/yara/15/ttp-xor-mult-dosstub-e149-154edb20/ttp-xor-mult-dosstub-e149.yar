rule TTP_XOR_MULT_DOSStub_e149 {
  strings:
    $key_e149 = { b5 21 [2] c1 39 [2] 86 3b [2] c1 2a [2] 8f 26 [2] 83 2c [2] 94 27 [2] 8f 69 [2] b2 }

  condition:
    any of them
}