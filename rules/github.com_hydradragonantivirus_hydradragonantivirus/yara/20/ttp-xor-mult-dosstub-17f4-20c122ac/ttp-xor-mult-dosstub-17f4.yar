rule TTP_XOR_MULT_DOSStub_17f4 {
  strings:
    $key_17f4 = { 43 9c [2] 37 84 [2] 70 86 [2] 37 97 [2] 79 9b [2] 75 91 [2] 62 9a [2] 79 d4 [2] 44 }

  condition:
    any of them
}