rule TTP_XOR_MULT_DOSStub_f519 {
  strings:
    $key_f519 = { a1 71 [2] d5 69 [2] 92 6b [2] d5 7a [2] 9b 76 [2] 97 7c [2] 80 77 [2] 9b 39 [2] a6 }

  condition:
    any of them
}