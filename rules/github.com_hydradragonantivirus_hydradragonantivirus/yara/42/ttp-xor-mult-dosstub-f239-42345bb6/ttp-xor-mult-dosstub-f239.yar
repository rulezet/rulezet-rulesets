rule TTP_XOR_MULT_DOSStub_f239 {
  strings:
    $key_f239 = { a6 51 [2] d2 49 [2] 95 4b [2] d2 5a [2] 9c 56 [2] 90 5c [2] 87 57 [2] 9c 19 [2] a1 }

  condition:
    any of them
}