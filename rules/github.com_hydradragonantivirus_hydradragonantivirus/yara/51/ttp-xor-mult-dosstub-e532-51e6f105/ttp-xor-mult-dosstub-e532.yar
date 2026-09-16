rule TTP_XOR_MULT_DOSStub_e532 {
  strings:
    $key_e532 = { b1 5a [2] c5 42 [2] 82 40 [2] c5 51 [2] 8b 5d [2] 87 57 [2] 90 5c [2] 8b 12 [2] b6 }

  condition:
    any of them
}