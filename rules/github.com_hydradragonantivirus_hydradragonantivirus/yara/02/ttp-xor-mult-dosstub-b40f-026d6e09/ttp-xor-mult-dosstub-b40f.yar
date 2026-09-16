rule TTP_XOR_MULT_DOSStub_b40f {
  strings:
    $key_b40f = { e0 67 [2] 94 7f [2] d3 7d [2] 94 6c [2] da 60 [2] d6 6a [2] c1 61 [2] da 2f [2] e7 }

  condition:
    any of them
}