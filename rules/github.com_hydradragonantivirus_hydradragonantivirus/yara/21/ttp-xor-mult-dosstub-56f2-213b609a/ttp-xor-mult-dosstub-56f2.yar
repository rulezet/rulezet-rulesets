rule TTP_XOR_MULT_DOSStub_56f2 {
  strings:
    $key_56f2 = { 02 9a [2] 76 82 [2] 31 80 [2] 76 91 [2] 38 9d [2] 34 97 [2] 23 9c [2] 38 d2 [2] 05 }

  condition:
    any of them
}