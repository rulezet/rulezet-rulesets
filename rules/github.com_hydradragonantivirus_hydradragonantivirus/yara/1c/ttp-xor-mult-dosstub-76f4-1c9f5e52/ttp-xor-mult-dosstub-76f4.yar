rule TTP_XOR_MULT_DOSStub_76f4 {
  strings:
    $key_76f4 = { 22 9c [2] 56 84 [2] 11 86 [2] 56 97 [2] 18 9b [2] 14 91 [2] 03 9a [2] 18 d4 [2] 25 }

  condition:
    any of them
}