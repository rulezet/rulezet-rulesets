rule TTP_XOR_MULT_DOSStub_17f9 {
  strings:
    $key_17f9 = { 43 91 [2] 37 89 [2] 70 8b [2] 37 9a [2] 79 96 [2] 75 9c [2] 62 97 [2] 79 d9 [2] 44 }

  condition:
    any of them
}