rule TTP_XOR_MULT_DOSStub_f3a9 {
  strings:
    $key_f3a9 = { a7 c1 [2] d3 d9 [2] 94 db [2] d3 ca [2] 9d c6 [2] 91 cc [2] 86 c7 [2] 9d 89 [2] a0 }

  condition:
    any of them
}