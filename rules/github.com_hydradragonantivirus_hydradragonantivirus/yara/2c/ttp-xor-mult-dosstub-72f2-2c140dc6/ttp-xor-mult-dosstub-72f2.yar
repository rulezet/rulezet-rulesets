rule TTP_XOR_MULT_DOSStub_72f2 {
  strings:
    $key_72f2 = { 26 9a [2] 52 82 [2] 15 80 [2] 52 91 [2] 1c 9d [2] 10 97 [2] 07 9c [2] 1c d2 [2] 21 }

  condition:
    any of them
}