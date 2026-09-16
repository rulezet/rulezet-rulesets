rule TTP_XOR_MULT_DOSStub_5d52 {
  strings:
    $key_5d52 = { 09 3a [2] 7d 22 [2] 3a 20 [2] 7d 31 [2] 33 3d [2] 3f 37 [2] 28 3c [2] 33 72 [2] 0e }

  condition:
    any of them
}