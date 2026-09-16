rule TTP_XOR_MULT_DOSStub_d6a3 {
  strings:
    $key_d6a3 = { 82 cb [2] f6 d3 [2] b1 d1 [2] f6 c0 [2] b8 cc [2] b4 c6 [2] a3 cd [2] b8 83 [2] 85 }

  condition:
    any of them
}