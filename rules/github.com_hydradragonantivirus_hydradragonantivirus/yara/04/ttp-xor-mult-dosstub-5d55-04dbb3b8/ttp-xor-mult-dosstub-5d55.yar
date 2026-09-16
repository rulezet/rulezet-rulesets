rule TTP_XOR_MULT_DOSStub_5d55 {
  strings:
    $key_5d55 = { 09 3d [2] 7d 25 [2] 3a 27 [2] 7d 36 [2] 33 3a [2] 3f 30 [2] 28 3b [2] 33 75 [2] 0e }

  condition:
    any of them
}