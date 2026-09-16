rule TTP_XOR_MULT_DOSStub_4d55 {
  strings:
    $key_4d55 = { 19 3d [2] 6d 25 [2] 2a 27 [2] 6d 36 [2] 23 3a [2] 2f 30 [2] 38 3b [2] 23 75 [2] 1e }

  condition:
    any of them
}