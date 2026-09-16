rule TTP_XOR_MULT_DOSStub_b338 {
  strings:
    $key_b338 = { e7 50 [2] 93 48 [2] d4 4a [2] 93 5b [2] dd 57 [2] d1 5d [2] c6 56 [2] dd 18 [2] e0 }

  condition:
    any of them
}