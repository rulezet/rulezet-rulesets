rule TTP_XOR_MULT_DOSStub_03f9 {
  strings:
    $key_03f9 = { 57 91 [2] 23 89 [2] 64 8b [2] 23 9a [2] 6d 96 [2] 61 9c [2] 76 97 [2] 6d d9 [2] 50 }

  condition:
    any of them
}