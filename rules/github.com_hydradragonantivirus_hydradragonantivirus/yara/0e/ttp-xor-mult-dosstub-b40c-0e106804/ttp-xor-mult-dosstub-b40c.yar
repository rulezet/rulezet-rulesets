rule TTP_XOR_MULT_DOSStub_b40c {
  strings:
    $key_b40c = { e0 64 [2] 94 7c [2] d3 7e [2] 94 6f [2] da 63 [2] d6 69 [2] c1 62 [2] da 2c [2] e7 }

  condition:
    any of them
}