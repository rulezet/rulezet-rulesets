rule TTP_XOR_MULT_DOSStub_6853 {
  strings:
    $key_6853 = { 3c 3b [2] 48 23 [2] 0f 21 [2] 48 30 [2] 06 3c [2] 0a 36 [2] 1d 3d [2] 06 73 [2] 3b }

  condition:
    any of them
}