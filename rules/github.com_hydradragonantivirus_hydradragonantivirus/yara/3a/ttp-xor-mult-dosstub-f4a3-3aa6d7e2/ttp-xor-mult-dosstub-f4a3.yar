rule TTP_XOR_MULT_DOSStub_f4a3 {
  strings:
    $key_f4a3 = { a0 cb [2] d4 d3 [2] 93 d1 [2] d4 c0 [2] 9a cc [2] 96 c6 [2] 81 cd [2] 9a 83 [2] a7 }

  condition:
    any of them
}