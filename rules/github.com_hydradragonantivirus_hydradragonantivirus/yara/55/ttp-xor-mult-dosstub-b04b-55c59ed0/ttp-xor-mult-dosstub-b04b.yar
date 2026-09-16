rule TTP_XOR_MULT_DOSStub_b04b {
  strings:
    $key_b04b = { e4 23 [2] 90 3b [2] d7 39 [2] 90 28 [2] de 24 [2] d2 2e [2] c5 25 [2] de 6b [2] e3 }

  condition:
    any of them
}