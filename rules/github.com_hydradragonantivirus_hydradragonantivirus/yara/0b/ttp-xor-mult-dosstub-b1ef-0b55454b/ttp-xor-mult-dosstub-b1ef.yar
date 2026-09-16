rule TTP_XOR_MULT_DOSStub_b1ef {
  strings:
    $key_b1ef = { e5 87 [2] 91 9f [2] d6 9d [2] 91 8c [2] df 80 [2] d3 8a [2] c4 81 [2] df cf [2] e2 }

  condition:
    any of them
}