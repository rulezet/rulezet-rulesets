rule TTP_XOR_MULT_DOSStub_7d58 {
  strings:
    $key_7d58 = { 29 30 [2] 5d 28 [2] 1a 2a [2] 5d 3b [2] 13 37 [2] 1f 3d [2] 08 36 [2] 13 78 [2] 2e }

  condition:
    any of them
}