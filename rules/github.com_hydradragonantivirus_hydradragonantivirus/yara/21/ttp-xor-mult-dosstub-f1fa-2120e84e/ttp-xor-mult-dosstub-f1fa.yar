rule TTP_XOR_MULT_DOSStub_f1fa {
  strings:
    $key_f1fa = { a5 92 [2] d1 8a [2] 96 88 [2] d1 99 [2] 9f 95 [2] 93 9f [2] 84 94 [2] 9f da [2] a2 }

  condition:
    any of them
}