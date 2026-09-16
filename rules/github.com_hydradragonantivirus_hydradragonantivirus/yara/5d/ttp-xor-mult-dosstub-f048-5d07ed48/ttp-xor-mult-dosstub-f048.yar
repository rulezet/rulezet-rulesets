rule TTP_XOR_MULT_DOSStub_f048 {
  strings:
    $key_f048 = { a4 20 [2] d0 38 [2] 97 3a [2] d0 2b [2] 9e 27 [2] 92 2d [2] 85 26 [2] 9e 68 [2] a3 }

  condition:
    any of them
}