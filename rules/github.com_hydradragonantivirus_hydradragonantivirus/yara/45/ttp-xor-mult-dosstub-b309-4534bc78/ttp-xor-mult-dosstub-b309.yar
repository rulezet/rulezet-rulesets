rule TTP_XOR_MULT_DOSStub_b309 {
  strings:
    $key_b309 = { e7 61 [2] 93 79 [2] d4 7b [2] 93 6a [2] dd 66 [2] d1 6c [2] c6 67 [2] dd 29 [2] e0 }

  condition:
    any of them
}