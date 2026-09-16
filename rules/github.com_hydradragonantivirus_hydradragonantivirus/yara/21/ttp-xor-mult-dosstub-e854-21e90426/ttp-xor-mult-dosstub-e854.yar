rule TTP_XOR_MULT_DOSStub_e854 {
  strings:
    $key_e854 = { bc 3c [2] c8 24 [2] 8f 26 [2] c8 37 [2] 86 3b [2] 8a 31 [2] 9d 3a [2] 86 74 [2] bb }

  condition:
    any of them
}