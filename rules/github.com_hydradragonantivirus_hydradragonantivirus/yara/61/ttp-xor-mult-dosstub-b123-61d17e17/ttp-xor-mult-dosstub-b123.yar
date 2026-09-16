rule TTP_XOR_MULT_DOSStub_b123 {
  strings:
    $key_b123 = { e5 4b [2] 91 53 [2] d6 51 [2] 91 40 [2] df 4c [2] d3 46 [2] c4 4d [2] df 03 [2] e2 }

  condition:
    any of them
}