rule TTP_XOR_MULT_DOSStub_b153 {
  strings:
    $key_b153 = { e5 3b [2] 91 23 [2] d6 21 [2] 91 30 [2] df 3c [2] d3 36 [2] c4 3d [2] df 73 [2] e2 }

  condition:
    any of them
}