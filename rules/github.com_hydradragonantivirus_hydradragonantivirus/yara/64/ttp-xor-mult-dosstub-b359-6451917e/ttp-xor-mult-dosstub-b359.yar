rule TTP_XOR_MULT_DOSStub_b359 {
  strings:
    $key_b359 = { e7 31 [2] 93 29 [2] d4 2b [2] 93 3a [2] dd 36 [2] d1 3c [2] c6 37 [2] dd 79 [2] e0 }

  condition:
    any of them
}