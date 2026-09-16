rule TTP_XOR_MULT_DOSStub_3855 {
  strings:
    $key_3855 = { 6c 3d [2] 18 25 [2] 5f 27 [2] 18 36 [2] 56 3a [2] 5a 30 [2] 4d 3b [2] 56 75 [2] 6b }

  condition:
    any of them
}