rule TTP_XOR_MULT_DOSStub_51f2 {
  strings:
    $key_51f2 = { 05 9a [2] 71 82 [2] 36 80 [2] 71 91 [2] 3f 9d [2] 33 97 [2] 24 9c [2] 3f d2 [2] 02 }

  condition:
    any of them
}