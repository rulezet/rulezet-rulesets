rule TTP_XOR_MULT_DOSStub_4f52 {
  strings:
    $key_4f52 = { 1b 3a [2] 6f 22 [2] 28 20 [2] 6f 31 [2] 21 3d [2] 2d 37 [2] 3a 3c [2] 21 72 [2] 1c }

  condition:
    any of them
}