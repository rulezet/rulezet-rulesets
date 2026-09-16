rule TTP_XOR_MULT_DOSStub_f745 {
  strings:
    $key_f745 = { a3 2d [2] d7 35 [2] 90 37 [2] d7 26 [2] 99 2a [2] 95 20 [2] 82 2b [2] 99 65 [2] a4 }

  condition:
    any of them
}