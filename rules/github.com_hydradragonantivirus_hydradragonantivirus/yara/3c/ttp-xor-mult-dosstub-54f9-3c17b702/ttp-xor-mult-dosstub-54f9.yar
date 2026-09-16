rule TTP_XOR_MULT_DOSStub_54f9 {
  strings:
    $key_54f9 = { 00 91 [2] 74 89 [2] 33 8b [2] 74 9a [2] 3a 96 [2] 36 9c [2] 21 97 [2] 3a d9 [2] 07 }

  condition:
    any of them
}