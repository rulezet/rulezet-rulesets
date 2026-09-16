rule TTP_XOR_MULT_DOSStub_b665 {
  strings:
    $key_b665 = { e2 0d [2] 96 15 [2] d1 17 [2] 96 06 [2] d8 0a [2] d4 00 [2] c3 0b [2] d8 45 [2] e5 }

  condition:
    any of them
}