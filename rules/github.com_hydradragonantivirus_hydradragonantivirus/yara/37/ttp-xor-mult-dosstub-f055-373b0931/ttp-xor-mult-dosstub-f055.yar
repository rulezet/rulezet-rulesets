rule TTP_XOR_MULT_DOSStub_f055 {
  strings:
    $key_f055 = { a4 3d [2] d0 25 [2] 97 27 [2] d0 36 [2] 9e 3a [2] 92 30 [2] 85 3b [2] 9e 75 [2] a3 }

  condition:
    any of them
}