rule TTP_XOR_MULT_DOSStub_b61e {
  strings:
    $key_b61e = { e2 76 [2] 96 6e [2] d1 6c [2] 96 7d [2] d8 71 [2] d4 7b [2] c3 70 [2] d8 3e [2] e5 }

  condition:
    any of them
}