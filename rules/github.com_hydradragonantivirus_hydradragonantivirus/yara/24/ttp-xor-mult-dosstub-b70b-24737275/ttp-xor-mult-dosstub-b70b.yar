rule TTP_XOR_MULT_DOSStub_b70b {
  strings:
    $key_b70b = { e3 63 [2] 97 7b [2] d0 79 [2] 97 68 [2] d9 64 [2] d5 6e [2] c2 65 [2] d9 2b [2] e4 }

  condition:
    any of them
}