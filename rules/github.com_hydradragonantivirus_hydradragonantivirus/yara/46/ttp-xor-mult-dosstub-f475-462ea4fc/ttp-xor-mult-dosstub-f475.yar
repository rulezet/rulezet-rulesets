rule TTP_XOR_MULT_DOSStub_f475 {
  strings:
    $key_f475 = { a0 1d [2] d4 05 [2] 93 07 [2] d4 16 [2] 9a 1a [2] 96 10 [2] 81 1b [2] 9a 55 [2] a7 }

  condition:
    any of them
}