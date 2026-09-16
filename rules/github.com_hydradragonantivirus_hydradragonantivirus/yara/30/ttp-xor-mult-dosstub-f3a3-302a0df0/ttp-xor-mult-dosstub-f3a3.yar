rule TTP_XOR_MULT_DOSStub_f3a3 {
  strings:
    $key_f3a3 = { a7 cb [2] d3 d3 [2] 94 d1 [2] d3 c0 [2] 9d cc [2] 91 c6 [2] 86 cd [2] 9d 83 [2] a0 }

  condition:
    any of them
}