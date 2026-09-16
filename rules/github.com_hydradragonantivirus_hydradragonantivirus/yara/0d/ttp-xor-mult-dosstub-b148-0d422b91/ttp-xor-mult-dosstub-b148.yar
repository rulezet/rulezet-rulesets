rule TTP_XOR_MULT_DOSStub_b148 {
  strings:
    $key_b148 = { e5 20 [2] 91 38 [2] d6 3a [2] 91 2b [2] df 27 [2] d3 2d [2] c4 26 [2] df 68 [2] e2 }

  condition:
    any of them
}