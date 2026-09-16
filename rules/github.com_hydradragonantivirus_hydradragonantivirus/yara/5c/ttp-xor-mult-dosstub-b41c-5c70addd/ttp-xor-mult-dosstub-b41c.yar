rule TTP_XOR_MULT_DOSStub_b41c {
  strings:
    $key_b41c = { e0 74 [2] 94 6c [2] d3 6e [2] 94 7f [2] da 73 [2] d6 79 [2] c1 72 [2] da 3c [2] e7 }

  condition:
    any of them
}