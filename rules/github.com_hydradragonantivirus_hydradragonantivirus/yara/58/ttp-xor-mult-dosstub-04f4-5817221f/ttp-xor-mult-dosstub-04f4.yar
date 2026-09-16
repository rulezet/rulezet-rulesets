rule TTP_XOR_MULT_DOSStub_04f4 {
  strings:
    $key_04f4 = { 50 9c [2] 24 84 [2] 63 86 [2] 24 97 [2] 6a 9b [2] 66 91 [2] 71 9a [2] 6a d4 [2] 57 }

  condition:
    any of them
}