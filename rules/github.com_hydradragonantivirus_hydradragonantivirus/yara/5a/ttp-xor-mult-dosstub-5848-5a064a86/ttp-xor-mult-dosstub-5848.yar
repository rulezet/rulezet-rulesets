rule TTP_XOR_MULT_DOSStub_5848 {
  strings:
    $key_5848 = { 0c 20 [2] 78 38 [2] 3f 3a [2] 78 2b [2] 36 27 [2] 3a 2d [2] 2d 26 [2] 36 68 [2] 0b }

  condition:
    any of them
}