rule TTP_XOR_MULT_DOSStub_b1ea {
  strings:
    $key_b1ea = { e5 82 [2] 91 9a [2] d6 98 [2] 91 89 [2] df 85 [2] d3 8f [2] c4 84 [2] df ca [2] e2 }

  condition:
    any of them
}