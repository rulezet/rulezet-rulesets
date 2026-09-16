rule TTP_XOR_MULT_DOSStub_b31f {
  strings:
    $key_b31f = { e7 77 [2] 93 6f [2] d4 6d [2] 93 7c [2] dd 70 [2] d1 7a [2] c6 71 [2] dd 3f [2] e0 }

  condition:
    any of them
}