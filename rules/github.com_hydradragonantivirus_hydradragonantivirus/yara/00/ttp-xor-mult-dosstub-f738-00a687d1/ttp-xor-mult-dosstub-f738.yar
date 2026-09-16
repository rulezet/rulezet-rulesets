rule TTP_XOR_MULT_DOSStub_f738 {
  strings:
    $key_f738 = { a3 50 [2] d7 48 [2] 90 4a [2] d7 5b [2] 99 57 [2] 95 5d [2] 82 56 [2] 99 18 [2] a4 }

  condition:
    any of them
}