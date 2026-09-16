rule TTP_XOR_MULT_DOSStub_b46c {
  strings:
    $key_b46c = { e0 04 [2] 94 1c [2] d3 1e [2] 94 0f [2] da 03 [2] d6 09 [2] c1 02 [2] da 4c [2] e7 }

  condition:
    any of them
}