rule TTP_XOR_MULT_DOSStub_22f2 {
  strings:
    $key_22f2 = { 76 9a [2] 02 82 [2] 45 80 [2] 02 91 [2] 4c 9d [2] 40 97 [2] 57 9c [2] 4c d2 [2] 71 }

  condition:
    any of them
}