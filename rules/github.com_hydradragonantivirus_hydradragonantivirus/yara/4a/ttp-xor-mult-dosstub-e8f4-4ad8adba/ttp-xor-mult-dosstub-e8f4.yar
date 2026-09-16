rule TTP_XOR_MULT_DOSStub_e8f4 {
  strings:
    $key_e8f4 = { bc 9c [2] c8 84 [2] 8f 86 [2] c8 97 [2] 86 9b [2] 8a 91 [2] 9d 9a [2] 86 d4 [2] bb }

  condition:
    any of them
}