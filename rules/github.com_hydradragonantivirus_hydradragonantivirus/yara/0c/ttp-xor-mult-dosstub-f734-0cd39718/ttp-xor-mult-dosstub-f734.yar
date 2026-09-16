rule TTP_XOR_MULT_DOSStub_f734 {
  strings:
    $key_f734 = { a3 5c [2] d7 44 [2] 90 46 [2] d7 57 [2] 99 5b [2] 95 51 [2] 82 5a [2] 99 14 [2] a4 }

  condition:
    any of them
}