rule TTP_XOR_MULT_DOSStub_76f9 {
  strings:
    $key_76f9 = { 22 91 [2] 56 89 [2] 11 8b [2] 56 9a [2] 18 96 [2] 14 9c [2] 03 97 [2] 18 d9 [2] 25 }

  condition:
    any of them
}