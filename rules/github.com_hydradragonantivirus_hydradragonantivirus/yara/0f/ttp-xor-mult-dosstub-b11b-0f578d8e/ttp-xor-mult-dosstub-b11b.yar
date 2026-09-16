rule TTP_XOR_MULT_DOSStub_b11b {
  strings:
    $key_b11b = { e5 73 [2] 91 6b [2] d6 69 [2] 91 78 [2] df 74 [2] d3 7e [2] c4 75 [2] df 3b [2] e2 }

  condition:
    any of them
}