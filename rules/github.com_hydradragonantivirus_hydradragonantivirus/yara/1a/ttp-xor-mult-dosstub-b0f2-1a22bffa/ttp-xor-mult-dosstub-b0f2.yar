rule TTP_XOR_MULT_DOSStub_b0f2 {
  strings:
    $key_b0f2 = { e4 9a [2] 90 82 [2] d7 80 [2] 90 91 [2] de 9d [2] d2 97 [2] c5 9c [2] de d2 [2] e3 }

  condition:
    any of them
}