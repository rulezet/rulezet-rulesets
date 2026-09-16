rule TTP_XOR_MULT_DOSStub_5835 {
  strings:
    $key_5835 = { 0c 5d [2] 78 45 [2] 3f 47 [2] 78 56 [2] 36 5a [2] 3a 50 [2] 2d 5b [2] 36 15 [2] 0b }

  condition:
    any of them
}