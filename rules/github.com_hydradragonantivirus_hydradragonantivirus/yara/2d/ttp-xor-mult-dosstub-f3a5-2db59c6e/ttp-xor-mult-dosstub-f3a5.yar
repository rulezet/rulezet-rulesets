rule TTP_XOR_MULT_DOSStub_f3a5 {
  strings:
    $key_f3a5 = { a7 cd [2] d3 d5 [2] 94 d7 [2] d3 c6 [2] 9d ca [2] 91 c0 [2] 86 cb [2] 9d 85 [2] a0 }

  condition:
    any of them
}