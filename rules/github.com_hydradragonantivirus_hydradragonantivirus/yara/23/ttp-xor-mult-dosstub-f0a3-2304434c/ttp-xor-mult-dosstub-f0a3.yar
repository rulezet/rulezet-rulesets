rule TTP_XOR_MULT_DOSStub_f0a3 {
  strings:
    $key_f0a3 = { a4 cb [2] d0 d3 [2] 97 d1 [2] d0 c0 [2] 9e cc [2] 92 c6 [2] 85 cd [2] 9e 83 [2] a3 }

  condition:
    any of them
}