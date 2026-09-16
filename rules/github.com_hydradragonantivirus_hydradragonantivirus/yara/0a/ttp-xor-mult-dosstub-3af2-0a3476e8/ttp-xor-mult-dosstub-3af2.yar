rule TTP_XOR_MULT_DOSStub_3af2 {
  strings:
    $key_3af2 = { 6e 9a [2] 1a 82 [2] 5d 80 [2] 1a 91 [2] 54 9d [2] 58 97 [2] 4f 9c [2] 54 d2 [2] 69 }

  condition:
    any of them
}