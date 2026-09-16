rule TTP_XOR_MULT_DOSStub_e8f8 {
  strings:
    $key_e8f8 = { bc 90 [2] c8 88 [2] 8f 8a [2] c8 9b [2] 86 97 [2] 8a 9d [2] 9d 96 [2] 86 d8 [2] bb }

  condition:
    any of them
}