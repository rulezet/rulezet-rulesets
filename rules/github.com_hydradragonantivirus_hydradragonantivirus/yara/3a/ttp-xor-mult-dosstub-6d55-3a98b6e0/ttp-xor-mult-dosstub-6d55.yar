rule TTP_XOR_MULT_DOSStub_6d55 {
  strings:
    $key_6d55 = { 39 3d [2] 4d 25 [2] 0a 27 [2] 4d 36 [2] 03 3a [2] 0f 30 [2] 18 3b [2] 03 75 [2] 3e }

  condition:
    any of them
}