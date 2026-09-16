rule TTP_XOR_MULT_DOSStub_f348 {
  strings:
    $key_f348 = { a7 20 [2] d3 38 [2] 94 3a [2] d3 2b [2] 9d 27 [2] 91 2d [2] 86 26 [2] 9d 68 [2] a0 }

  condition:
    any of them
}