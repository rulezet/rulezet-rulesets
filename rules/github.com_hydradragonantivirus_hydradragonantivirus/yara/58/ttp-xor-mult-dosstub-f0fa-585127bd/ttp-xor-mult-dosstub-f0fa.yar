rule TTP_XOR_MULT_DOSStub_f0fa {
  strings:
    $key_f0fa = { a4 92 [2] d0 8a [2] 97 88 [2] d0 99 [2] 9e 95 [2] 92 9f [2] 85 94 [2] 9e da [2] a3 }

  condition:
    any of them
}