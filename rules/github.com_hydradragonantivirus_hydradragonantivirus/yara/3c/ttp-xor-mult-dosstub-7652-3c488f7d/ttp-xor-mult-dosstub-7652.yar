rule TTP_XOR_MULT_DOSStub_7652 {
  strings:
    $key_7652 = { 22 3a [2] 56 22 [2] 11 20 [2] 56 31 [2] 18 3d [2] 14 37 [2] 03 3c [2] 18 72 [2] 25 }

  condition:
    any of them
}