rule TTP_XOR_MULT_DOSStub_46f9 {
  strings:
    $key_46f9 = { 12 91 [2] 66 89 [2] 21 8b [2] 66 9a [2] 28 96 [2] 24 9c [2] 33 97 [2] 28 d9 [2] 15 }

  condition:
    any of them
}