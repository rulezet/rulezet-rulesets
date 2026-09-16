rule TTP_XOR_MULT_DOSStub_b403 {
  strings:
    $key_b403 = { e0 6b [2] 94 73 [2] d3 71 [2] 94 60 [2] da 6c [2] d6 66 [2] c1 6d [2] da 23 [2] e7 }

  condition:
    any of them
}