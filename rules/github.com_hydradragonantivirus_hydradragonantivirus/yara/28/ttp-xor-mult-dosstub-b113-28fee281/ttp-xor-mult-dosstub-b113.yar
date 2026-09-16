rule TTP_XOR_MULT_DOSStub_b113 {
  strings:
    $key_b113 = { e5 7b [2] 91 63 [2] d6 61 [2] 91 70 [2] df 7c [2] d3 76 [2] c4 7d [2] df 33 [2] e2 }

  condition:
    any of them
}