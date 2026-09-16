rule TTP_XOR_MULT_DOSStub_b322 {
  strings:
    $key_b322 = { e7 4a [2] 93 52 [2] d4 50 [2] 93 41 [2] dd 4d [2] d1 47 [2] c6 4c [2] dd 02 [2] e0 }

  condition:
    any of them
}