rule TTP_XOR_MULT_DOSStub_13f2 {
  strings:
    $key_13f2 = { 47 9a [2] 33 82 [2] 74 80 [2] 33 91 [2] 7d 9d [2] 71 97 [2] 66 9c [2] 7d d2 [2] 40 }

  condition:
    any of them
}