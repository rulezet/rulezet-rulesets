rule TTP_XOR_MULT_DOSStub_b67e {
  strings:
    $key_b67e = { e2 16 [2] 96 0e [2] d1 0c [2] 96 1d [2] d8 11 [2] d4 1b [2] c3 10 [2] d8 5e [2] e5 }

  condition:
    any of them
}