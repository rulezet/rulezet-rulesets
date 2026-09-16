rule TTP_XOR_MULT_DOSStub_e815 {
  strings:
    $key_e815 = { bc 7d [2] c8 65 [2] 8f 67 [2] c8 76 [2] 86 7a [2] 8a 70 [2] 9d 7b [2] 86 35 [2] bb }

  condition:
    any of them
}