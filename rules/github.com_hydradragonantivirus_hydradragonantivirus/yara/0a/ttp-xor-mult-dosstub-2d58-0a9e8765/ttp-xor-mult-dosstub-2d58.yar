rule TTP_XOR_MULT_DOSStub_2d58 {
  strings:
    $key_2d58 = { 79 30 [2] 0d 28 [2] 4a 2a [2] 0d 3b [2] 43 37 [2] 4f 3d [2] 58 36 [2] 43 78 [2] 7e }

  condition:
    any of them
}