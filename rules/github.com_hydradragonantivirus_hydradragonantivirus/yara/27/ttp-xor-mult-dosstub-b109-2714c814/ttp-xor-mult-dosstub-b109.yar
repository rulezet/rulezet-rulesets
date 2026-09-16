rule TTP_XOR_MULT_DOSStub_b109 {
  strings:
    $key_b109 = { e5 61 [2] 91 79 [2] d6 7b [2] 91 6a [2] df 66 [2] d3 6c [2] c4 67 [2] df 29 [2] e2 }

  condition:
    any of them
}