rule TTP_XOR_MULT_DOSStub_f248 {
  strings:
    $key_f248 = { a6 20 [2] d2 38 [2] 95 3a [2] d2 2b [2] 9c 27 [2] 90 2d [2] 87 26 [2] 9c 68 [2] a1 }

  condition:
    any of them
}