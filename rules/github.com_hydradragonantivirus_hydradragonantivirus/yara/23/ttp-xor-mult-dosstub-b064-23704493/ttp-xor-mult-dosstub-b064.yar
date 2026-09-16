rule TTP_XOR_MULT_DOSStub_b064 {
  strings:
    $key_b064 = { e4 0c [2] 90 14 [2] d7 16 [2] 90 07 [2] de 0b [2] d2 01 [2] c5 0a [2] de 44 [2] e3 }

  condition:
    any of them
}