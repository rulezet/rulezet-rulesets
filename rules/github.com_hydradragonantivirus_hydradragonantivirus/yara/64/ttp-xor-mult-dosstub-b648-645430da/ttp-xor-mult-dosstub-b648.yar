rule TTP_XOR_MULT_DOSStub_b648 {
  strings:
    $key_b648 = { e2 20 [2] 96 38 [2] d1 3a [2] 96 2b [2] d8 27 [2] d4 2d [2] c3 26 [2] d8 68 [2] e5 }

  condition:
    any of them
}