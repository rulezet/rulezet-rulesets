rule TTP_XOR_MULT_DOSStub_75f4 {
  strings:
    $key_75f4 = { 21 9c [2] 55 84 [2] 12 86 [2] 55 97 [2] 1b 9b [2] 17 91 [2] 00 9a [2] 1b d4 [2] 26 }

  condition:
    any of them
}