rule TTP_XOR_MULT_DOSStub_b638 {
  strings:
    $key_b638 = { e2 50 [2] 96 48 [2] d1 4a [2] 96 5b [2] d8 57 [2] d4 5d [2] c3 56 [2] d8 18 [2] e5 }

  condition:
    any of them
}