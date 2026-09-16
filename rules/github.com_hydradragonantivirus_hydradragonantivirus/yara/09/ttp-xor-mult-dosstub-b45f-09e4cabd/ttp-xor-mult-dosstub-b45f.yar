rule TTP_XOR_MULT_DOSStub_b45f {
  strings:
    $key_b45f = { e0 37 [2] 94 2f [2] d3 2d [2] 94 3c [2] da 30 [2] d6 3a [2] c1 31 [2] da 7f [2] e7 }

  condition:
    any of them
}