rule TTP_XOR_MULT_DOSStub_b37a {
  strings:
    $key_b37a = { e7 12 [2] 93 0a [2] d4 08 [2] 93 19 [2] dd 15 [2] d1 1f [2] c6 14 [2] dd 5a [2] e0 }

  condition:
    any of them
}