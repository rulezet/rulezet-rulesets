rule TTP_XOR_MULT_DOSStub_b608 {
  strings:
    $key_b608 = { e2 60 [2] 96 78 [2] d1 7a [2] 96 6b [2] d8 67 [2] d4 6d [2] c3 66 [2] d8 28 [2] e5 }

  condition:
    any of them
}