rule TTP_XOR_MULT_DOSStub_22f4 {
  strings:
    $key_22f4 = { 76 9c [2] 02 84 [2] 45 86 [2] 02 97 [2] 4c 9b [2] 40 91 [2] 57 9a [2] 4c d4 [2] 71 }

  condition:
    any of them
}