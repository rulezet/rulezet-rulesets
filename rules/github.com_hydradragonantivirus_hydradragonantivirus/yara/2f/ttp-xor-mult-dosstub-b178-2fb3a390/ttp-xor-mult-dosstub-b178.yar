rule TTP_XOR_MULT_DOSStub_b178 {
  strings:
    $key_b178 = { e5 10 [2] 91 08 [2] d6 0a [2] 91 1b [2] df 17 [2] d3 1d [2] c4 16 [2] df 58 [2] e2 }

  condition:
    any of them
}