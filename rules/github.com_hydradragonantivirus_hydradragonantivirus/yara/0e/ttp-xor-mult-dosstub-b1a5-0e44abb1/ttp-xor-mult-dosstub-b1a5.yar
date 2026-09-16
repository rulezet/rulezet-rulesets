rule TTP_XOR_MULT_DOSStub_b1a5 {
  strings:
    $key_b1a5 = { e5 cd [2] 91 d5 [2] d6 d7 [2] 91 c6 [2] df ca [2] d3 c0 [2] c4 cb [2] df 85 [2] e2 }

  condition:
    any of them
}