rule TTP_XOR_MULT_DOSStub_b16b {
  strings:
    $key_b16b = { e5 03 [2] 91 1b [2] d6 19 [2] 91 08 [2] df 04 [2] d3 0e [2] c4 05 [2] df 4b [2] e2 }

  condition:
    any of them
}