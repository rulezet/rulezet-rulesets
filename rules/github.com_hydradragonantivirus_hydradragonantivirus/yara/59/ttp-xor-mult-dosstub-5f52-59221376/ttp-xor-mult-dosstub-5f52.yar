rule TTP_XOR_MULT_DOSStub_5f52 {
  strings:
    $key_5f52 = { 0b 3a [2] 7f 22 [2] 38 20 [2] 7f 31 [2] 31 3d [2] 3d 37 [2] 2a 3c [2] 31 72 [2] 0c }

  condition:
    any of them
}