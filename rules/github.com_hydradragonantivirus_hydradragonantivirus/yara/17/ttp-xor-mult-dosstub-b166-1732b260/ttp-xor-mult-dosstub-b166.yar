rule TTP_XOR_MULT_DOSStub_b166 {
  strings:
    $key_b166 = { e5 0e [2] 91 16 [2] d6 14 [2] 91 05 [2] df 09 [2] d3 03 [2] c4 08 [2] df 46 [2] e2 }

  condition:
    any of them
}