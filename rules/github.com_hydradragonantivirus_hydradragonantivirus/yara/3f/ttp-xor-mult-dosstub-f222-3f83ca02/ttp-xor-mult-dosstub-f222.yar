rule TTP_XOR_MULT_DOSStub_f222 {
  strings:
    $key_f222 = { a6 4a [2] d2 52 [2] 95 50 [2] d2 41 [2] 9c 4d [2] 90 47 [2] 87 4c [2] 9c 02 [2] a1 }

  condition:
    any of them
}