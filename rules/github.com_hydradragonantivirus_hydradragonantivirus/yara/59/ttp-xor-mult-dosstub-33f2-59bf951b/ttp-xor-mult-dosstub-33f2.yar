rule TTP_XOR_MULT_DOSStub_33f2 {
  strings:
    $key_33f2 = { 67 9a [2] 13 82 [2] 54 80 [2] 13 91 [2] 5d 9d [2] 51 97 [2] 46 9c [2] 5d d2 [2] 60 }

  condition:
    any of them
}