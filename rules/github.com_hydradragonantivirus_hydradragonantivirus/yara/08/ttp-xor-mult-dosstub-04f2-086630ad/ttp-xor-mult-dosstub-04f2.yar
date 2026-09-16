rule TTP_XOR_MULT_DOSStub_04f2 {
  strings:
    $key_04f2 = { 50 9a [2] 24 82 [2] 63 80 [2] 24 91 [2] 6a 9d [2] 66 97 [2] 71 9c [2] 6a d2 [2] 57 }

  condition:
    any of them
}