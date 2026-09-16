rule TTP_XOR_MULT_DOSStub_5875 {
  strings:
    $key_5875 = { 0c 1d [2] 78 05 [2] 3f 07 [2] 78 16 [2] 36 1a [2] 3a 10 [2] 2d 1b [2] 36 55 [2] 0b }

  condition:
    any of them
}