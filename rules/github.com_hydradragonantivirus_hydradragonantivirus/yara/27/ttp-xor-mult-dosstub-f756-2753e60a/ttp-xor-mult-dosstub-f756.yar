rule TTP_XOR_MULT_DOSStub_f756 {
  strings:
    $key_f756 = { a3 3e [2] d7 26 [2] 90 24 [2] d7 35 [2] 99 39 [2] 95 33 [2] 82 38 [2] 99 76 [2] a4 }

  condition:
    any of them
}