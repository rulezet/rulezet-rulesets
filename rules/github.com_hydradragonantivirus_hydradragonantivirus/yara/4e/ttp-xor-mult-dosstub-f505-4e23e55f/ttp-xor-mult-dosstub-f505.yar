rule TTP_XOR_MULT_DOSStub_f505 {
  strings:
    $key_f505 = { a1 6d [2] d5 75 [2] 92 77 [2] d5 66 [2] 9b 6a [2] 97 60 [2] 80 6b [2] 9b 25 [2] a6 }

  condition:
    any of them
}