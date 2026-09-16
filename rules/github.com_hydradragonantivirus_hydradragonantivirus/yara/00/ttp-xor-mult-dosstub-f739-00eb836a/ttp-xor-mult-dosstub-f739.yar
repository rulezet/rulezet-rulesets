rule TTP_XOR_MULT_DOSStub_f739 {
  strings:
    $key_f739 = { a3 51 [2] d7 49 [2] 90 4b [2] d7 5a [2] 99 56 [2] 95 5c [2] 82 57 [2] 99 19 [2] a4 }

  condition:
    any of them
}