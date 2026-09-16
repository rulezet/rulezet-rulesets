rule TTP_XOR_MULT_DOSStub_3f52 {
  strings:
    $key_3f52 = { 6b 3a [2] 1f 22 [2] 58 20 [2] 1f 31 [2] 51 3d [2] 5d 37 [2] 4a 3c [2] 51 72 [2] 6c }

  condition:
    any of them
}