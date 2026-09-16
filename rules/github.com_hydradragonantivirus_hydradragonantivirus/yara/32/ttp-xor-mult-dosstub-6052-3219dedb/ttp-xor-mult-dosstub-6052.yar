rule TTP_XOR_MULT_DOSStub_6052 {
  strings:
    $key_6052 = { 34 3a [2] 40 22 [2] 07 20 [2] 40 31 [2] 0e 3d [2] 02 37 [2] 15 3c [2] 0e 72 [2] 33 }

  condition:
    any of them
}