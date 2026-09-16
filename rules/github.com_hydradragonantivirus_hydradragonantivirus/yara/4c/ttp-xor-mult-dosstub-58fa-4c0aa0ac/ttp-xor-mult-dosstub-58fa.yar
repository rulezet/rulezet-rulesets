rule TTP_XOR_MULT_DOSStub_58fa {
  strings:
    $key_58fa = { 0c 92 [2] 78 8a [2] 3f 88 [2] 78 99 [2] 36 95 [2] 3a 9f [2] 2d 94 [2] 36 da [2] 0b }

  condition:
    any of them
}