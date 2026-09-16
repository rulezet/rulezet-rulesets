rule TTP_XOR_MULT_DOSStub_1a52 {
  strings:
    $key_1a52 = { 4e 3a [2] 3a 22 [2] 7d 20 [2] 3a 31 [2] 74 3d [2] 78 37 [2] 6f 3c [2] 74 72 [2] 49 }

  condition:
    any of them
}