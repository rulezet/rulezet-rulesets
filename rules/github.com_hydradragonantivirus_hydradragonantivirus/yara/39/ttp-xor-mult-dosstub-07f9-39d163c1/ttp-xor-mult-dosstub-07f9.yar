rule TTP_XOR_MULT_DOSStub_07f9 {
  strings:
    $key_07f9 = { 53 91 [2] 27 89 [2] 60 8b [2] 27 9a [2] 69 96 [2] 65 9c [2] 72 97 [2] 69 d9 [2] 54 }

  condition:
    any of them
}