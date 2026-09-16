rule TTP_XOR_MULT_DOSStub_f252 {
  strings:
    $key_f252 = { a6 3a [2] d2 22 [2] 95 20 [2] d2 31 [2] 9c 3d [2] 90 37 [2] 87 3c [2] 9c 72 [2] a1 }

  condition:
    any of them
}