rule TTP_XOR_MULT_DOSStub_f049 {
  strings:
    $key_f049 = { a4 21 [2] d0 39 [2] 97 3b [2] d0 2a [2] 9e 26 [2] 92 2c [2] 85 27 [2] 9e 69 [2] a3 }

  condition:
    any of them
}