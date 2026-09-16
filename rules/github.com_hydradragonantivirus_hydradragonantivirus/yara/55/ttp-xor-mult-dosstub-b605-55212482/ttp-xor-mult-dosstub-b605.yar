rule TTP_XOR_MULT_DOSStub_b605 {
  strings:
    $key_b605 = { e2 6d [2] 96 75 [2] d1 77 [2] 96 66 [2] d8 6a [2] d4 60 [2] c3 6b [2] d8 25 [2] e5 }

  condition:
    any of them
}