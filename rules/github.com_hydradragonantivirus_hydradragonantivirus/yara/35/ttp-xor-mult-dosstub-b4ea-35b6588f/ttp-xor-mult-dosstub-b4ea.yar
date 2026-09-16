rule TTP_XOR_MULT_DOSStub_b4ea {
  strings:
    $key_b4ea = { e0 82 [2] 94 9a [2] d3 98 [2] 94 89 [2] da 85 [2] d6 8f [2] c1 84 [2] da ca [2] e7 }

  condition:
    any of them
}