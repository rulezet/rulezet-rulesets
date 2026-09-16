rule TTP_XOR_MULT_DOSStub_1f58 {
  strings:
    $key_1f58 = { 4b 30 [2] 3f 28 [2] 78 2a [2] 3f 3b [2] 71 37 [2] 7d 3d [2] 6a 36 [2] 71 78 [2] 4c }

  condition:
    any of them
}