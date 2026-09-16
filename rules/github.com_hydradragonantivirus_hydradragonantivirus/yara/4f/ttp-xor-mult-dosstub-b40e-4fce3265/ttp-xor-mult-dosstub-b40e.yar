rule TTP_XOR_MULT_DOSStub_b40e {
  strings:
    $key_b40e = { e0 66 [2] 94 7e [2] d3 7c [2] 94 6d [2] da 61 [2] d6 6b [2] c1 60 [2] da 2e [2] e7 }

  condition:
    any of them
}