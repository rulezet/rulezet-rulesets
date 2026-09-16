rule TTP_XOR_MULT_DOSStub_b36a {
  strings:
    $key_b36a = { e7 02 [2] 93 1a [2] d4 18 [2] 93 09 [2] dd 05 [2] d1 0f [2] c6 04 [2] dd 4a [2] e0 }

  condition:
    any of them
}