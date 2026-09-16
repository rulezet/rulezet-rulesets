rule TTP_XOR_MULT_DOSStub_f038 {
  strings:
    $key_f038 = { a4 50 [2] d0 48 [2] 97 4a [2] d0 5b [2] 9e 57 [2] 92 5d [2] 85 56 [2] 9e 18 [2] a3 }

  condition:
    any of them
}