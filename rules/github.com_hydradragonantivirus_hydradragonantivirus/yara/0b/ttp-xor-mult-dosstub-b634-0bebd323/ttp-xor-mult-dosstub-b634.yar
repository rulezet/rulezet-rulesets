rule TTP_XOR_MULT_DOSStub_b634 {
  strings:
    $key_b634 = { e2 5c [2] 96 44 [2] d1 46 [2] 96 57 [2] d8 5b [2] d4 51 [2] c3 5a [2] d8 14 [2] e5 }

  condition:
    any of them
}