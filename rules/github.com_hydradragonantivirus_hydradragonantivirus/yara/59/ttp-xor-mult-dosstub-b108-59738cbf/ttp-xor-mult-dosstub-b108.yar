rule TTP_XOR_MULT_DOSStub_b108 {
  strings:
    $key_b108 = { e5 60 [2] 91 78 [2] d6 7a [2] 91 6b [2] df 67 [2] d3 6d [2] c4 66 [2] df 28 [2] e2 }

  condition:
    any of them
}