rule TTP_XOR_MULT_DOSStub_b12b {
  strings:
    $key_b12b = { e5 43 [2] 91 5b [2] d6 59 [2] 91 48 [2] df 44 [2] d3 4e [2] c4 45 [2] df 0b [2] e2 }

  condition:
    any of them
}