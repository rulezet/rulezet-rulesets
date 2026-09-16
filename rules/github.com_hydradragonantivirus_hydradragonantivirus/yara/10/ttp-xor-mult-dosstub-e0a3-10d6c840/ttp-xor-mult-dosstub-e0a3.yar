rule TTP_XOR_MULT_DOSStub_e0a3 {
  strings:
    $key_e0a3 = { b4 cb [2] c0 d3 [2] 87 d1 [2] c0 c0 [2] 8e cc [2] 82 c6 [2] 95 cd [2] 8e 83 [2] b3 }

  condition:
    any of them
}