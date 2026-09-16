rule TTP_XOR_MULT_DOSStub_b468 {
  strings:
    $key_b468 = { e0 00 [2] 94 18 [2] d3 1a [2] 94 0b [2] da 07 [2] d6 0d [2] c1 06 [2] da 48 [2] e7 }

  condition:
    any of them
}