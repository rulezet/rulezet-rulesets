rule TTP_XOR_MULT_DOSStub_71f2 {
  strings:
    $key_71f2 = { 25 9a [2] 51 82 [2] 16 80 [2] 51 91 [2] 1f 9d [2] 13 97 [2] 04 9c [2] 1f d2 [2] 22 }

  condition:
    any of them
}