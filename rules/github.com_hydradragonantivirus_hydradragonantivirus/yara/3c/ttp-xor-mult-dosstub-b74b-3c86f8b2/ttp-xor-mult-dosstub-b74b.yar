rule TTP_XOR_MULT_DOSStub_b74b {
  strings:
    $key_b74b = { e3 23 [2] 97 3b [2] d0 39 [2] 97 28 [2] d9 24 [2] d5 2e [2] c2 25 [2] d9 6b [2] e4 }

  condition:
    any of them
}