rule TTP_XOR_MULT_DOSStub_31f2 {
  strings:
    $key_31f2 = { 65 9a [2] 11 82 [2] 56 80 [2] 11 91 [2] 5f 9d [2] 53 97 [2] 44 9c [2] 5f d2 [2] 62 }

  condition:
    any of them
}