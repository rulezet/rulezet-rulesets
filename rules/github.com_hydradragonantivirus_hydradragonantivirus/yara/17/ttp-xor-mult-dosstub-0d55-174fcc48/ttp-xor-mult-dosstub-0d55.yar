rule TTP_XOR_MULT_DOSStub_0d55 {
  strings:
    $key_0d55 = { 59 3d [2] 2d 25 [2] 6a 27 [2] 2d 36 [2] 63 3a [2] 6f 30 [2] 78 3b [2] 63 75 [2] 5e }

  condition:
    any of them
}