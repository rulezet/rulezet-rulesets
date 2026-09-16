rule TTP_XOR_MULT_DOSStub_b622 {
  strings:
    $key_b622 = { e2 4a [2] 96 52 [2] d1 50 [2] 96 41 [2] d8 4d [2] d4 47 [2] c3 4c [2] d8 02 [2] e5 }

  condition:
    any of them
}