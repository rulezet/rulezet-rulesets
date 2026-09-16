rule TTP_XOR_MULT_DOSStub_f005 {
  strings:
    $key_f005 = { a4 6d [2] d0 75 [2] 97 77 [2] d0 66 [2] 9e 6a [2] 92 60 [2] 85 6b [2] 9e 25 [2] a3 }

  condition:
    any of them
}