rule TTP_XOR_MULT_DOSStub_6352 {
  strings:
    $key_6352 = { 37 3a [2] 43 22 [2] 04 20 [2] 43 31 [2] 0d 3d [2] 01 37 [2] 16 3c [2] 0d 72 [2] 30 }

  condition:
    any of them
}