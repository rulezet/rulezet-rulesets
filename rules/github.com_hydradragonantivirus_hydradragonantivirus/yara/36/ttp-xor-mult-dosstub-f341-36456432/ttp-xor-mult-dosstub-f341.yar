rule TTP_XOR_MULT_DOSStub_f341 {
  strings:
    $key_f341 = { a7 29 [2] d3 31 [2] 94 33 [2] d3 22 [2] 9d 2e [2] 91 24 [2] 86 2f [2] 9d 61 [2] a0 }

  condition:
    any of them
}