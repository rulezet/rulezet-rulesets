rule TTP_XOR_MULT_DOSStub_f233 {
  strings:
    $key_f233 = { a6 5b [2] d2 43 [2] 95 41 [2] d2 50 [2] 9c 5c [2] 90 56 [2] 87 5d [2] 9c 13 [2] a1 }

  condition:
    any of them
}