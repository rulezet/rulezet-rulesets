rule TTP_XOR_MULT_DOSStub_22f9 {
  strings:
    $key_22f9 = { 76 91 [2] 02 89 [2] 45 8b [2] 02 9a [2] 4c 96 [2] 40 9c [2] 57 97 [2] 4c d9 [2] 71 }

  condition:
    any of them
}