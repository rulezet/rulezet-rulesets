rule TTP_XOR_MULT_DOSStub_f3ae {
  strings:
    $key_f3ae = { a7 c6 [2] d3 de [2] 94 dc [2] d3 cd [2] 9d c1 [2] 91 cb [2] 86 c0 [2] 9d 8e [2] a0 }

  condition:
    any of them
}