rule TTP_XOR_MULT_DOSStub_b0e3 {
  strings:
    $key_b0e3 = { e4 8b [2] 90 93 [2] d7 91 [2] 90 80 [2] de 8c [2] d2 86 [2] c5 8d [2] de c3 [2] e3 }

  condition:
    any of them
}