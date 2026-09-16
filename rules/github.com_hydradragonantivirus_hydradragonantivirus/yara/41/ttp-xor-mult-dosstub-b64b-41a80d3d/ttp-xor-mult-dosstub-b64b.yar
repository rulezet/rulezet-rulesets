rule TTP_XOR_MULT_DOSStub_b64b {
  strings:
    $key_b64b = { e2 23 [2] 96 3b [2] d1 39 [2] 96 28 [2] d8 24 [2] d4 2e [2] c3 25 [2] d8 6b [2] e5 }

  condition:
    any of them
}