rule TTP_XOR_MULT_DOSStub_f14b {
  strings:
    $key_f14b = { a5 23 [2] d1 3b [2] 96 39 [2] d1 28 [2] 9f 24 [2] 93 2e [2] 84 25 [2] 9f 6b [2] a2 }

  condition:
    any of them
}