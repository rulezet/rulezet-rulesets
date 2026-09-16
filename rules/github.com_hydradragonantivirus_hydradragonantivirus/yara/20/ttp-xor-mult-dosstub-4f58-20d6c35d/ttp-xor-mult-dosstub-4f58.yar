rule TTP_XOR_MULT_DOSStub_4f58 {
  strings:
    $key_4f58 = { 1b 30 [2] 6f 28 [2] 28 2a [2] 6f 3b [2] 21 37 [2] 2d 3d [2] 3a 36 [2] 21 78 [2] 1c }

  condition:
    any of them
}