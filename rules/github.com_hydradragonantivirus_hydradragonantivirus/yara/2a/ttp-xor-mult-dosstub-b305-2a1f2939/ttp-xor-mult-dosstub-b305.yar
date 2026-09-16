rule TTP_XOR_MULT_DOSStub_b305 {
  strings:
    $key_b305 = { e7 6d [2] 93 75 [2] d4 77 [2] 93 66 [2] dd 6a [2] d1 60 [2] c6 6b [2] dd 25 [2] e0 }

  condition:
    any of them
}