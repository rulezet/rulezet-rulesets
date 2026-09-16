rule TTP_XOR_MULT_DOSStub_f052 {
  strings:
    $key_f052 = { a4 3a [2] d0 22 [2] 97 20 [2] d0 31 [2] 9e 3d [2] 92 37 [2] 85 3c [2] 9e 72 [2] a3 }

  condition:
    any of them
}