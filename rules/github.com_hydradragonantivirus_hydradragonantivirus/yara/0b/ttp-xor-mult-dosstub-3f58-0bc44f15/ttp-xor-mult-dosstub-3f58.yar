rule TTP_XOR_MULT_DOSStub_3f58 {
  strings:
    $key_3f58 = { 6b 30 [2] 1f 28 [2] 58 2a [2] 1f 3b [2] 51 37 [2] 5d 3d [2] 4a 36 [2] 51 78 [2] 6c }

  condition:
    any of them
}