rule TTP_XOR_MULT_DOSStub_531b {
  strings:
    $key_531b = { 07 73 [2] 73 6b [2] 34 69 [2] 73 78 [2] 3d 74 [2] 31 7e [2] 26 75 [2] 3d 3b [2] 00 }

  condition:
    any of them
}