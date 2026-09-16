rule TTP_XOR_MULT_DOSStub_f045 {
  strings:
    $key_f045 = { a4 2d [2] d0 35 [2] 97 37 [2] d0 26 [2] 9e 2a [2] 92 20 [2] 85 2b [2] 9e 65 [2] a3 }

  condition:
    any of them
}