rule TTP_XOR_MULT_DOSStub_43f2 {
  strings:
    $key_43f2 = { 17 9a [2] 63 82 [2] 24 80 [2] 63 91 [2] 2d 9d [2] 21 97 [2] 36 9c [2] 2d d2 [2] 10 }

  condition:
    any of them
}