rule TTP_XOR_MULT_DOSStub_6858 {
  strings:
    $key_6858 = { 3c 30 [2] 48 28 [2] 0f 2a [2] 48 3b [2] 06 37 [2] 0a 3d [2] 1d 36 [2] 06 78 [2] 3b }

  condition:
    any of them
}