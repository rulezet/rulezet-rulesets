rule TTP_XOR_MULT_DOSStub_f018 {
  strings:
    $key_f018 = { a4 70 [2] d0 68 [2] 97 6a [2] d0 7b [2] 9e 77 [2] 92 7d [2] 85 76 [2] 9e 38 [2] a3 }

  condition:
    any of them
}