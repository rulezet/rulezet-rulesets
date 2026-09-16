rule TTP_XOR_MULT_DOSStub_41f2 {
  strings:
    $key_41f2 = { 15 9a [2] 61 82 [2] 26 80 [2] 61 91 [2] 2f 9d [2] 23 97 [2] 34 9c [2] 2f d2 [2] 12 }

  condition:
    any of them
}