rule TTP_XOR_MULT_DOSStub_f218 {
  strings:
    $key_f218 = { a6 70 [2] d2 68 [2] 95 6a [2] d2 7b [2] 9c 77 [2] 90 7d [2] 87 76 [2] 9c 38 [2] a1 }

  condition:
    any of them
}