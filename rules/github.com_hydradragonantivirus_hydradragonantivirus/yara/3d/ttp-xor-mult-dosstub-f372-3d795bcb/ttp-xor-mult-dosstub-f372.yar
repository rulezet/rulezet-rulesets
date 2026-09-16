rule TTP_XOR_MULT_DOSStub_f372 {
  strings:
    $key_f372 = { a7 1a [2] d3 02 [2] 94 00 [2] d3 11 [2] 9d 1d [2] 91 17 [2] 86 1c [2] 9d 52 [2] a0 }

  condition:
    any of them
}