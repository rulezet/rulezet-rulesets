rule TTP_XOR_MULT_DOSStub_72f4 {
  strings:
    $key_72f4 = { 26 9c [2] 52 84 [2] 15 86 [2] 52 97 [2] 1c 9b [2] 10 91 [2] 07 9a [2] 1c d4 [2] 21 }

  condition:
    any of them
}