rule TTP_XOR_MULT_DOSStub_b073 {
  strings:
    $key_b073 = { e4 1b [2] 90 03 [2] d7 01 [2] 90 10 [2] de 1c [2] d2 16 [2] c5 1d [2] de 53 [2] e3 }

  condition:
    any of them
}