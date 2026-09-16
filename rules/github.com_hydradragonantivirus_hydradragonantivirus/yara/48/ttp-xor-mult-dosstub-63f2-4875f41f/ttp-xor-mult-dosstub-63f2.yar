rule TTP_XOR_MULT_DOSStub_63f2 {
  strings:
    $key_63f2 = { 37 9a [2] 43 82 [2] 04 80 [2] 43 91 [2] 0d 9d [2] 01 97 [2] 16 9c [2] 0d d2 [2] 30 }

  condition:
    any of them
}