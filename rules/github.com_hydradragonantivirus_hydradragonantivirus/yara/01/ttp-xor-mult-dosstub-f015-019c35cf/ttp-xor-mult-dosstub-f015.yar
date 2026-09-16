rule TTP_XOR_MULT_DOSStub_f015 {
  strings:
    $key_f015 = { a4 7d [2] d0 65 [2] 97 67 [2] d0 76 [2] 9e 7a [2] 92 70 [2] 85 7b [2] 9e 35 [2] a3 }

  condition:
    any of them
}