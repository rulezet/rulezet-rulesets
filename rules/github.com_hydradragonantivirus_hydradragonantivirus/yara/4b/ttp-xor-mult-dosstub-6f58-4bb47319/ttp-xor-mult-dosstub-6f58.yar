rule TTP_XOR_MULT_DOSStub_6f58 {
  strings:
    $key_6f58 = { 3b 30 [2] 4f 28 [2] 08 2a [2] 4f 3b [2] 01 37 [2] 0d 3d [2] 1a 36 [2] 01 78 [2] 3c }

  condition:
    any of them
}