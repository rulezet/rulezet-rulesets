rule TTP_XOR_MULT_DOSStub_f3a0 {
  strings:
    $key_f3a0 = { a7 c8 [2] d3 d0 [2] 94 d2 [2] d3 c3 [2] 9d cf [2] 91 c5 [2] 86 ce [2] 9d 80 [2] a0 }

  condition:
    any of them
}