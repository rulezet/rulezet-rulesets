rule TTP_XOR_MULT_DOSStub_5a52 {
  strings:
    $key_5a52 = { 0e 3a [2] 7a 22 [2] 3d 20 [2] 7a 31 [2] 34 3d [2] 38 37 [2] 2f 3c [2] 34 72 [2] 09 }

  condition:
    any of them
}