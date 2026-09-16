rule TTP_XOR_MULT_DOSStub_b36f {
  strings:
    $key_b36f = { e7 07 [2] 93 1f [2] d4 1d [2] 93 0c [2] dd 00 [2] d1 0a [2] c6 01 [2] dd 4f [2] e0 }

  condition:
    any of them
}