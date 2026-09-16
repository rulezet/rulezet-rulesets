rule TTP_XOR_MULT_DOSStub_b6e5 {
  strings:
    $key_b6e5 = { e2 8d [2] 96 95 [2] d1 97 [2] 96 86 [2] d8 8a [2] d4 80 [2] c3 8b [2] d8 c5 [2] e5 }

  condition:
    any of them
}