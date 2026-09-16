rule TTP_XOR_MULT_DOSStub_f172 {
  strings:
    $key_f172 = { a5 1a [2] d1 02 [2] 96 00 [2] d1 11 [2] 9f 1d [2] 93 17 [2] 84 1c [2] 9f 52 [2] a2 }

  condition:
    any of them
}