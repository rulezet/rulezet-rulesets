rule TTP_XOR_MULT_DOSStub_b4ba {
  strings:
    $key_b4ba = { e0 d2 [2] 94 ca [2] d3 c8 [2] 94 d9 [2] da d5 [2] d6 df [2] c1 d4 [2] da 9a [2] e7 }

  condition:
    any of them
}