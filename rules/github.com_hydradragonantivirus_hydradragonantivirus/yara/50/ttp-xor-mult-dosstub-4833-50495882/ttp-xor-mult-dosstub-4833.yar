rule TTP_XOR_MULT_DOSStub_4833 {
  strings:
    $key_4833 = { 1c 5b [2] 68 43 [2] 2f 41 [2] 68 50 [2] 26 5c [2] 2a 56 [2] 3d 5d [2] 26 13 [2] 1b }

  condition:
    any of them
}