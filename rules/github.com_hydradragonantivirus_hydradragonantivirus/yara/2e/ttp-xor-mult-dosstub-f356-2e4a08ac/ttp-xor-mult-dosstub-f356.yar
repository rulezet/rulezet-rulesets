rule TTP_XOR_MULT_DOSStub_f356 {
  strings:
    $key_f356 = { a7 3e [2] d3 26 [2] 94 24 [2] d3 35 [2] 9d 39 [2] 91 33 [2] 86 38 [2] 9d 76 [2] a0 }

  condition:
    any of them
}