rule TTP_XOR_MULT_DOSStub_b197 {
  strings:
    $key_b197 = { e5 ff [2] 91 e7 [2] d6 e5 [2] 91 f4 [2] df f8 [2] d3 f2 [2] c4 f9 [2] df b7 [2] e2 }

  condition:
    any of them
}