rule TTP_XOR_MULT_DOSStub_c0a3 {
  strings:
    $key_c0a3 = { 94 cb [2] e0 d3 [2] a7 d1 [2] e0 c0 [2] ae cc [2] a2 c6 [2] b5 cd [2] ae 83 [2] 93 }

  condition:
    any of them
}