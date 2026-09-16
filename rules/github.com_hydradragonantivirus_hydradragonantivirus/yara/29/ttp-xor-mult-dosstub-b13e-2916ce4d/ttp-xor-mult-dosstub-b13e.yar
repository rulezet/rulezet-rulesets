rule TTP_XOR_MULT_DOSStub_b13e {
  strings:
    $key_b13e = { e5 56 [2] 91 4e [2] d6 4c [2] 91 5d [2] df 51 [2] d3 5b [2] c4 50 [2] df 1e [2] e2 }

  condition:
    any of them
}