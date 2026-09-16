rule TTP_XOR_MULT_DOSStub_b42f {
  strings:
    $key_b42f = { e0 47 [2] 94 5f [2] d3 5d [2] 94 4c [2] da 40 [2] d6 4a [2] c1 41 [2] da 0f [2] e7 }

  condition:
    any of them
}