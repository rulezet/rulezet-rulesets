rule TTP_XOR_MULT_DOSStub_b713 {
  strings:
    $key_b713 = { e3 7b [2] 97 63 [2] d0 61 [2] 97 70 [2] d9 7c [2] d5 76 [2] c2 7d [2] d9 33 [2] e4 }

  condition:
    any of them
}