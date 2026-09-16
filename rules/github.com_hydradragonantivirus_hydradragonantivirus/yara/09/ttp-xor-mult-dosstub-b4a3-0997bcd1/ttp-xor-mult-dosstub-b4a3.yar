rule TTP_XOR_MULT_DOSStub_b4a3 {
  strings:
    $key_b4a3 = { e0 cb [2] 94 d3 [2] d3 d1 [2] 94 c0 [2] da cc [2] d6 c6 [2] c1 cd [2] da 83 [2] e7 }

  condition:
    any of them
}