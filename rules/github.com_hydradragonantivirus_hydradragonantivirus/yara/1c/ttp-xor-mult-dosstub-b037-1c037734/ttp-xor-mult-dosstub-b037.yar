rule TTP_XOR_MULT_DOSStub_b037 {
  strings:
    $key_b037 = { e4 5f [2] 90 47 [2] d7 45 [2] 90 54 [2] de 58 [2] d2 52 [2] c5 59 [2] de 17 [2] e3 }

  condition:
    any of them
}