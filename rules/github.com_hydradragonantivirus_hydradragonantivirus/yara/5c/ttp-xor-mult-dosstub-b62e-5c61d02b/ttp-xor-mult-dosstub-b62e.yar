rule TTP_XOR_MULT_DOSStub_b62e {
  strings:
    $key_b62e = { e2 46 [2] 96 5e [2] d1 5c [2] 96 4d [2] d8 41 [2] d4 4b [2] c3 40 [2] d8 0e [2] e5 }

  condition:
    any of them
}