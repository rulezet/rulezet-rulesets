rule TTP_XOR_MULT_DOSStub_b635 {
  strings:
    $key_b635 = { e2 5d [2] 96 45 [2] d1 47 [2] 96 56 [2] d8 5a [2] d4 50 [2] c3 5b [2] d8 15 [2] e5 }

  condition:
    any of them
}