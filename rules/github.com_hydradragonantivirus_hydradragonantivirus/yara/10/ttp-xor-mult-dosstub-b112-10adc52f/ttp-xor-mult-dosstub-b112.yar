rule TTP_XOR_MULT_DOSStub_b112 {
  strings:
    $key_b112 = { e5 7a [2] 91 62 [2] d6 60 [2] 91 71 [2] df 7d [2] d3 77 [2] c4 7c [2] df 32 [2] e2 }

  condition:
    any of them
}