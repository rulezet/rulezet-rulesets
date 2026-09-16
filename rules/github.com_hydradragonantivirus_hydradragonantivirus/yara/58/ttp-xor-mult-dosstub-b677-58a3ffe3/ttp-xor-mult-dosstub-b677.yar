rule TTP_XOR_MULT_DOSStub_b677 {
  strings:
    $key_b677 = { e2 1f [2] 96 07 [2] d1 05 [2] 96 14 [2] d8 18 [2] d4 12 [2] c3 19 [2] d8 57 [2] e5 }

  condition:
    any of them
}