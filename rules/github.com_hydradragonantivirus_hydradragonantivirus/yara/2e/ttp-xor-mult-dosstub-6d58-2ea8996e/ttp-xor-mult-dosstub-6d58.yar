rule TTP_XOR_MULT_DOSStub_6d58 {
  strings:
    $key_6d58 = { 39 30 [2] 4d 28 [2] 0a 2a [2] 4d 3b [2] 03 37 [2] 0f 3d [2] 18 36 [2] 03 78 [2] 3e }

  condition:
    any of them
}