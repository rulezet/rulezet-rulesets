rule TTP_XOR_MULT_DOSStub_f3a8 {
  strings:
    $key_f3a8 = { a7 c0 [2] d3 d8 [2] 94 da [2] d3 cb [2] 9d c7 [2] 91 cd [2] 86 c6 [2] 9d 88 [2] a0 }

  condition:
    any of them
}