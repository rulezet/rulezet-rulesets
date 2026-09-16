rule TTP_XOR_MULT_DOSStub_b144 {
  strings:
    $key_b144 = { e5 2c [2] 91 34 [2] d6 36 [2] 91 27 [2] df 2b [2] d3 21 [2] c4 2a [2] df 64 [2] e2 }

  condition:
    any of them
}