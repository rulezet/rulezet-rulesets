rule TTP_XOR_MULT_DOSStub_74f2 {
  strings:
    $key_74f2 = { 20 9a [2] 54 82 [2] 13 80 [2] 54 91 [2] 1a 9d [2] 16 97 [2] 01 9c [2] 1a d2 [2] 27 }

  condition:
    any of them
}