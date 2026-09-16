rule TTP_XOR_MULT_DOSStub_b03e {
  strings:
    $key_b03e = { e4 56 [2] 90 4e [2] d7 4c [2] 90 5d [2] de 51 [2] d2 5b [2] c5 50 [2] de 1e [2] e3 }

  condition:
    any of them
}