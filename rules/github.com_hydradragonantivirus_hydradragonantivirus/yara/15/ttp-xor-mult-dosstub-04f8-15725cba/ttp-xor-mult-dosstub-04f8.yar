rule TTP_XOR_MULT_DOSStub_04f8 {
  strings:
    $key_04f8 = { 50 90 [2] 24 88 [2] 63 8a [2] 24 9b [2] 6a 97 [2] 66 9d [2] 71 96 [2] 6a d8 [2] 57 }

  condition:
    any of them
}