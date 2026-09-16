rule TTP_XOR_MULT_DOSStub_b4ed {
  strings:
    $key_b4ed = { e0 85 [2] 94 9d [2] d3 9f [2] 94 8e [2] da 82 [2] d6 88 [2] c1 83 [2] da cd [2] e7 }

  condition:
    any of them
}