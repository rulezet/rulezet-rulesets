rule TTP_XOR_MULT_DOSStub_f3b9 {
  strings:
    $key_f3b9 = { a7 d1 [2] d3 c9 [2] 94 cb [2] d3 da [2] 9d d6 [2] 91 dc [2] 86 d7 [2] 9d 99 [2] a0 }

  condition:
    any of them
}