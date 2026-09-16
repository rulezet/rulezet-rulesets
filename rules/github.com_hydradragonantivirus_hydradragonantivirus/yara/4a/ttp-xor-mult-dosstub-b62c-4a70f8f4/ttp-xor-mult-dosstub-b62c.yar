rule TTP_XOR_MULT_DOSStub_b62c {
  strings:
    $key_b62c = { e2 44 [2] 96 5c [2] d1 5e [2] 96 4f [2] d8 43 [2] d4 49 [2] c3 42 [2] d8 0c [2] e5 }

  condition:
    any of them
}