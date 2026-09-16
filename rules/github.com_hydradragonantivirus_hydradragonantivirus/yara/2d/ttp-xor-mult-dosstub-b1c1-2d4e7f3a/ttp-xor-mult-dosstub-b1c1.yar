rule TTP_XOR_MULT_DOSStub_b1c1 {
  strings:
    $key_b1c1 = { e5 a9 [2] 91 b1 [2] d6 b3 [2] 91 a2 [2] df ae [2] d3 a4 [2] c4 af [2] df e1 [2] e2 }

  condition:
    any of them
}