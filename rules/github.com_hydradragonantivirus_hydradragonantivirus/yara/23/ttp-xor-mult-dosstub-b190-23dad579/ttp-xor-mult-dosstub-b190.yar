rule TTP_XOR_MULT_DOSStub_b190 {
  strings:
    $key_b190 = { e5 f8 [2] 91 e0 [2] d6 e2 [2] 91 f3 [2] df ff [2] d3 f5 [2] c4 fe [2] df b0 [2] e2 }

  condition:
    any of them
}