rule TTP_XOR_MULT_DOSStub_b325 {
  strings:
    $key_b325 = { e7 4d [2] 93 55 [2] d4 57 [2] 93 46 [2] dd 4a [2] d1 40 [2] c6 4b [2] dd 05 [2] e0 }

  condition:
    any of them
}