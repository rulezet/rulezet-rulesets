rule TTP_XOR_MULT_DOSStub_b754 {
  strings:
    $key_b754 = { e3 3c [2] 97 24 [2] d0 26 [2] 97 37 [2] d9 3b [2] d5 31 [2] c2 3a [2] d9 74 [2] e4 }

  condition:
    any of them
}