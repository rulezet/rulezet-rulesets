rule TTP_XOR_MULT_DOSStub_f059 {
  strings:
    $key_f059 = { a4 31 [2] d0 29 [2] 97 2b [2] d0 3a [2] 9e 36 [2] 92 3c [2] 85 37 [2] 9e 79 [2] a3 }

  condition:
    any of them
}