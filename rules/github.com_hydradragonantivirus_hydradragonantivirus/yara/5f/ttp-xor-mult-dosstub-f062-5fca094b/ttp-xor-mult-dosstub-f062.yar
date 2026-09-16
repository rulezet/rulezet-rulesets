rule TTP_XOR_MULT_DOSStub_f062 {
  strings:
    $key_f062 = { a4 0a [2] d0 12 [2] 97 10 [2] d0 01 [2] 9e 0d [2] 92 07 [2] 85 0c [2] 9e 42 [2] a3 }

  condition:
    any of them
}