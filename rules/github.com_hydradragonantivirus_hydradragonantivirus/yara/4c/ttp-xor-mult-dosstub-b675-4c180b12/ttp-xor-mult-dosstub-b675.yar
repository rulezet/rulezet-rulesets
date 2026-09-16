rule TTP_XOR_MULT_DOSStub_b675 {
  strings:
    $key_b675 = { e2 1d [2] 96 05 [2] d1 07 [2] 96 16 [2] d8 1a [2] d4 10 [2] c3 1b [2] d8 55 [2] e5 }

  condition:
    any of them
}