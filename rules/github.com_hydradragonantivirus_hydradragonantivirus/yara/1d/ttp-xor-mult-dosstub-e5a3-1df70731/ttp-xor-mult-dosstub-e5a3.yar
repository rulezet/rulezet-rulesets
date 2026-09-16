rule TTP_XOR_MULT_DOSStub_e5a3 {
  strings:
    $key_e5a3 = { b1 cb [2] c5 d3 [2] 82 d1 [2] c5 c0 [2] 8b cc [2] 87 c6 [2] 90 cd [2] 8b 83 [2] b6 }

  condition:
    any of them
}