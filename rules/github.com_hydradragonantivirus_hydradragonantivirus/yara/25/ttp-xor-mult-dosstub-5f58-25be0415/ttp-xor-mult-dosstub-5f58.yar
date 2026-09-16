rule TTP_XOR_MULT_DOSStub_5f58 {
  strings:
    $key_5f58 = { 0b 30 [2] 7f 28 [2] 38 2a [2] 7f 3b [2] 31 37 [2] 3d 3d [2] 2a 36 [2] 31 78 [2] 0c }

  condition:
    any of them
}