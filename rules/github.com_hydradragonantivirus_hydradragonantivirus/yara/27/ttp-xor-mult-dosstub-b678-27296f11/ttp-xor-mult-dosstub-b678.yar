rule TTP_XOR_MULT_DOSStub_b678 {
  strings:
    $key_b678 = { e2 10 [2] 96 08 [2] d1 0a [2] 96 1b [2] d8 17 [2] d4 1d [2] c3 16 [2] d8 58 [2] e5 }

  condition:
    any of them
}