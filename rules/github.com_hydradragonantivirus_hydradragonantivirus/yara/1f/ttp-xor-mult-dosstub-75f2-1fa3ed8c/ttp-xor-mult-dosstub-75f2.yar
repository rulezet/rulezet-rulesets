rule TTP_XOR_MULT_DOSStub_75f2 {
  strings:
    $key_75f2 = { 21 9a [2] 55 82 [2] 12 80 [2] 55 91 [2] 1b 9d [2] 17 97 [2] 00 9c [2] 1b d2 [2] 26 }

  condition:
    any of them
}