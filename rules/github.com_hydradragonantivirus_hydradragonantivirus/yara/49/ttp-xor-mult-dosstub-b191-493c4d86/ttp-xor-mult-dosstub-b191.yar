rule TTP_XOR_MULT_DOSStub_b191 {
  strings:
    $key_b191 = { e5 f9 [2] 91 e1 [2] d6 e3 [2] 91 f2 [2] df fe [2] d3 f4 [2] c4 ff [2] df b1 [2] e2 }

  condition:
    any of them
}