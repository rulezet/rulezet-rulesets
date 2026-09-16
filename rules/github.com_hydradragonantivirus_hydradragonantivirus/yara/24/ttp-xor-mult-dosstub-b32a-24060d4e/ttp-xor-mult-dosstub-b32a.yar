rule TTP_XOR_MULT_DOSStub_b32a {
  strings:
    $key_b32a = { e7 42 [2] 93 5a [2] d4 58 [2] 93 49 [2] dd 45 [2] d1 4f [2] c6 44 [2] dd 0a [2] e0 }

  condition:
    any of them
}