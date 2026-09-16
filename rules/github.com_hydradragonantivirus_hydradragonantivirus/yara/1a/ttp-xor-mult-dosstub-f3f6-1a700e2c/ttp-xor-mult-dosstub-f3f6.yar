rule TTP_XOR_MULT_DOSStub_f3f6 {
  strings:
    $key_f3f6 = { a7 9e [2] d3 86 [2] 94 84 [2] d3 95 [2] 9d 99 [2] 91 93 [2] 86 98 [2] 9d d6 [2] a0 }

  condition:
    any of them
}