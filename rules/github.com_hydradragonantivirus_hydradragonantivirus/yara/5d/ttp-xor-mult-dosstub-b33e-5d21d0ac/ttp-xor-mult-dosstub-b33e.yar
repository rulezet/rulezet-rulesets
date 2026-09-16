rule TTP_XOR_MULT_DOSStub_b33e {
  strings:
    $key_b33e = { e7 56 [2] 93 4e [2] d4 4c [2] 93 5d [2] dd 51 [2] d1 5b [2] c6 50 [2] dd 1e [2] e0 }

  condition:
    any of them
}