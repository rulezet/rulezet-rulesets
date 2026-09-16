rule TTP_XOR_MULT_DOSStub_b162 {
  strings:
    $key_b162 = { e5 0a [2] 91 12 [2] d6 10 [2] 91 01 [2] df 0d [2] d3 07 [2] c4 0c [2] df 42 [2] e2 }

  condition:
    any of them
}