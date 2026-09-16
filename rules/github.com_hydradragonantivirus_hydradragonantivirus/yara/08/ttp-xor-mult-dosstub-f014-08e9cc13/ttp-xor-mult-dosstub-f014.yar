rule TTP_XOR_MULT_DOSStub_f014 {
  strings:
    $key_f014 = { a4 7c [2] d0 64 [2] 97 66 [2] d0 77 [2] 9e 7b [2] 92 71 [2] 85 7a [2] 9e 34 [2] a3 }

  condition:
    any of them
}