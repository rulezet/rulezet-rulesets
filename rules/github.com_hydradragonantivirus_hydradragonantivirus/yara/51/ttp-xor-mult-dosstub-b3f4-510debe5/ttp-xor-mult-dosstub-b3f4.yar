rule TTP_XOR_MULT_DOSStub_b3f4 {
  strings:
    $key_b3f4 = { e7 9c [2] 93 84 [2] d4 86 [2] 93 97 [2] dd 9b [2] d1 91 [2] c6 9a [2] dd d4 [2] e0 }

  condition:
    any of them
}