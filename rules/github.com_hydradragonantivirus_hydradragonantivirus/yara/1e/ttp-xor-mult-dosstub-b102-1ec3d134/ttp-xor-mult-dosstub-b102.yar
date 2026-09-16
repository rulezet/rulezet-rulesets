rule TTP_XOR_MULT_DOSStub_b102 {
  strings:
    $key_b102 = { e5 6a [2] 91 72 [2] d6 70 [2] 91 61 [2] df 6d [2] d3 67 [2] c4 6c [2] df 22 [2] e2 }

  condition:
    any of them
}