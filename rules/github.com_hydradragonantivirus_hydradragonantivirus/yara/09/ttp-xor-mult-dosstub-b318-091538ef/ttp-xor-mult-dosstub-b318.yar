rule TTP_XOR_MULT_DOSStub_b318 {
  strings:
    $key_b318 = { e7 70 [2] 93 68 [2] d4 6a [2] 93 7b [2] dd 77 [2] d1 7d [2] c6 76 [2] dd 38 [2] e0 }

  condition:
    any of them
}