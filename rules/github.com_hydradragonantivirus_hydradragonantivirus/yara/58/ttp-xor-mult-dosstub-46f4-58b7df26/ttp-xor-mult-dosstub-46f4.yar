rule TTP_XOR_MULT_DOSStub_46f4 {
  strings:
    $key_46f4 = { 12 9c [2] 66 84 [2] 21 86 [2] 66 97 [2] 28 9b [2] 24 91 [2] 33 9a [2] 28 d4 [2] 15 }

  condition:
    any of them
}