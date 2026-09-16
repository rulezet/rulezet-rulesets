rule TTP_XOR_MULT_DOSStub_f377 {
  strings:
    $key_f377 = { a7 1f [2] d3 07 [2] 94 05 [2] d3 14 [2] 9d 18 [2] 91 12 [2] 86 19 [2] 9d 57 [2] a0 }

  condition:
    any of them
}