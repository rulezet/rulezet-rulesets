rule TTP_XOR_MULT_DOSStub_b655 {
  strings:
    $key_b655 = { e2 3d [2] 96 25 [2] d1 27 [2] 96 36 [2] d8 3a [2] d4 30 [2] c3 3b [2] d8 75 [2] e5 }

  condition:
    any of them
}