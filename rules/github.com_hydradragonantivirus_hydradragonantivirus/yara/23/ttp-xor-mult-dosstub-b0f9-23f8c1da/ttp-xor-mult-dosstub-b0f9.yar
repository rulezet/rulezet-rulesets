rule TTP_XOR_MULT_DOSStub_b0f9 {
  strings:
    $key_b0f9 = { e4 91 [2] 90 89 [2] d7 8b [2] 90 9a [2] de 96 [2] d2 9c [2] c5 97 [2] de d9 [2] e3 }

  condition:
    any of them
}