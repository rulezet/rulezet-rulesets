rule TTP_XOR_MULT_DOSStub_f5a3 {
  strings:
    $key_f5a3 = { a1 cb [2] d5 d3 [2] 92 d1 [2] d5 c0 [2] 9b cc [2] 97 c6 [2] 80 cd [2] 9b 83 [2] a6 }

  condition:
    any of them
}