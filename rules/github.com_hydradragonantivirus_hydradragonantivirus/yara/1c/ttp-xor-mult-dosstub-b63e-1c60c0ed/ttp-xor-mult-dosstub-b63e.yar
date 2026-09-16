rule TTP_XOR_MULT_DOSStub_b63e {
  strings:
    $key_b63e = { e2 56 [2] 96 4e [2] d1 4c [2] 96 5d [2] d8 51 [2] d4 5b [2] c3 50 [2] d8 1e [2] e5 }

  condition:
    any of them
}