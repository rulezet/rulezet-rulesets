rule TTP_XOR_MULT_DOSStub_e349 {
  strings:
    $key_e349 = { b7 21 [2] c3 39 [2] 84 3b [2] c3 2a [2] 8d 26 [2] 81 2c [2] 96 27 [2] 8d 69 [2] b0 }

  condition:
    any of them
}