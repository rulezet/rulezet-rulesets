rule TTP_XOR_MULT_DOSStub_b314 {
  strings:
    $key_b314 = { e7 7c [2] 93 64 [2] d4 66 [2] 93 77 [2] dd 7b [2] d1 71 [2] c6 7a [2] dd 34 [2] e0 }

  condition:
    any of them
}