rule TTP_XOR_MULT_DOSStub_3d58 {
  strings:
    $key_3d58 = { 69 30 [2] 1d 28 [2] 5a 2a [2] 1d 3b [2] 53 37 [2] 5f 3d [2] 48 36 [2] 53 78 [2] 6e }

  condition:
    any of them
}