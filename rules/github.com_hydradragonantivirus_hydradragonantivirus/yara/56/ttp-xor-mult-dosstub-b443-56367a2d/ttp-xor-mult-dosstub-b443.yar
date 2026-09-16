rule TTP_XOR_MULT_DOSStub_b443 {
  strings:
    $key_b443 = { e0 2b [2] 94 33 [2] d3 31 [2] 94 20 [2] da 2c [2] d6 26 [2] c1 2d [2] da 63 [2] e7 }

  condition:
    any of them
}