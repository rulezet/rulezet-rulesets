rule TTP_XOR_MULT_DOSStub_e1a3 {
  strings:
    $key_e1a3 = { b5 cb [2] c1 d3 [2] 86 d1 [2] c1 c0 [2] 8f cc [2] 83 c6 [2] 94 cd [2] 8f 83 [2] b2 }

  condition:
    any of them
}