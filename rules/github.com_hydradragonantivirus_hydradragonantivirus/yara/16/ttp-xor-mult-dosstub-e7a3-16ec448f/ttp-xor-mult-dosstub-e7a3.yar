rule TTP_XOR_MULT_DOSStub_e7a3 {
  strings:
    $key_e7a3 = { b3 cb [2] c7 d3 [2] 80 d1 [2] c7 c0 [2] 89 cc [2] 85 c6 [2] 92 cd [2] 89 83 [2] b4 }

  condition:
    any of them
}