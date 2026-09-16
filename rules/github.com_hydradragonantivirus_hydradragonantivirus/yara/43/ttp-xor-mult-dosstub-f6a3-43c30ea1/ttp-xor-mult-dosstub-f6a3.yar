rule TTP_XOR_MULT_DOSStub_f6a3 {
  strings:
    $key_f6a3 = { a2 cb [2] d6 d3 [2] 91 d1 [2] d6 c0 [2] 98 cc [2] 94 c6 [2] 83 cd [2] 98 83 [2] a5 }

  condition:
    any of them
}