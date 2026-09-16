rule TTP_XOR_MULT_DOSStub_b0f4 {
  strings:
    $key_b0f4 = { e4 9c [2] 90 84 [2] d7 86 [2] 90 97 [2] de 9b [2] d2 91 [2] c5 9a [2] de d4 [2] e3 }

  condition:
    any of them
}