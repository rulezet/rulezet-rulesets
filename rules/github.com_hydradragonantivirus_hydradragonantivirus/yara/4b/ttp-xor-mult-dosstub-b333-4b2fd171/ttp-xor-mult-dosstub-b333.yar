rule TTP_XOR_MULT_DOSStub_b333 {
  strings:
    $key_b333 = { e7 5b [2] 93 43 [2] d4 41 [2] 93 50 [2] dd 5c [2] d1 56 [2] c6 5d [2] dd 13 [2] e0 }

  condition:
    any of them
}