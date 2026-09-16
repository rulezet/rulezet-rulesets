rule TTP_XOR_MULT_DOSStub_b066 {
  strings:
    $key_b066 = { e4 0e [2] 90 16 [2] d7 14 [2] 90 05 [2] de 09 [2] d2 03 [2] c5 08 [2] de 46 [2] e3 }

  condition:
    any of them
}