rule TTP_XOR_MULT_DOSStub_b652 {
  strings:
    $key_b652 = { e2 3a [2] 96 22 [2] d1 20 [2] 96 31 [2] d8 3d [2] d4 37 [2] c3 3c [2] d8 72 [2] e5 }

  condition:
    any of them
}