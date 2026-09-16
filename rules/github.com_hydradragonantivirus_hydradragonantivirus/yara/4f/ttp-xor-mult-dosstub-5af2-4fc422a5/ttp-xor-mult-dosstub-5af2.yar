rule TTP_XOR_MULT_DOSStub_5af2 {
  strings:
    $key_5af2 = { 0e 9a [2] 7a 82 [2] 3d 80 [2] 7a 91 [2] 34 9d [2] 38 97 [2] 2f 9c [2] 34 d2 [2] 09 }

  condition:
    any of them
}