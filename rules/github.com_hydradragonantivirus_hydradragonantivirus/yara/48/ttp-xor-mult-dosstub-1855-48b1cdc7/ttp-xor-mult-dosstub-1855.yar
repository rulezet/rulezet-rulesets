rule TTP_XOR_MULT_DOSStub_1855 {
  strings:
    $key_1855 = { 4c 3d [2] 38 25 [2] 7f 27 [2] 38 36 [2] 76 3a [2] 7a 30 [2] 6d 3b [2] 76 75 [2] 4b }

  condition:
    any of them
}