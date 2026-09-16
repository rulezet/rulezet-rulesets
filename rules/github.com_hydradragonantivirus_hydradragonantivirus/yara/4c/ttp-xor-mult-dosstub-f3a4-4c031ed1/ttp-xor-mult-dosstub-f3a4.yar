rule TTP_XOR_MULT_DOSStub_f3a4 {
  strings:
    $key_f3a4 = { a7 cc [2] d3 d4 [2] 94 d6 [2] d3 c7 [2] 9d cb [2] 91 c1 [2] 86 ca [2] 9d 84 [2] a0 }

  condition:
    any of them
}