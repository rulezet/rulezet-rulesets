rule TTP_XOR_MULT_DOSStub_b61b {
  strings:
    $key_b61b = { e2 73 [2] 96 6b [2] d1 69 [2] 96 78 [2] d8 74 [2] d4 7e [2] c3 75 [2] d8 3b [2] e5 }

  condition:
    any of them
}