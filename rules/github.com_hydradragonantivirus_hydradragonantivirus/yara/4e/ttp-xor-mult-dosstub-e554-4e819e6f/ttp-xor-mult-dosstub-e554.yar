rule TTP_XOR_MULT_DOSStub_e554 {
  strings:
    $key_e554 = { b1 3c [2] c5 24 [2] 82 26 [2] c5 37 [2] 8b 3b [2] 87 31 [2] 90 3a [2] 8b 74 [2] b6 }

  condition:
    any of them
}