rule TTP_XOR_MULT_DOSStub_76f2 {
  strings:
    $key_76f2 = { 22 9a [2] 56 82 [2] 11 80 [2] 56 91 [2] 18 9d [2] 14 97 [2] 03 9c [2] 18 d2 [2] 25 }

  condition:
    any of them
}