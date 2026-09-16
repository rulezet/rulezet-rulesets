rule TTP_XOR_MULT_DOSStub_7d55 {
  strings:
    $key_7d55 = { 29 3d [2] 5d 25 [2] 1a 27 [2] 5d 36 [2] 13 3a [2] 1f 30 [2] 08 3b [2] 13 75 [2] 2e }

  condition:
    any of them
}