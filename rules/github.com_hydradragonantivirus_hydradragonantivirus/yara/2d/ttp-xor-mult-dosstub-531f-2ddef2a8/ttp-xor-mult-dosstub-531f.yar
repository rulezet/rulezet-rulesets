rule TTP_XOR_MULT_DOSStub_531f {
  strings:
    $key_531f = { 07 77 [2] 73 6f [2] 34 6d [2] 73 7c [2] 3d 70 [2] 31 7a [2] 26 71 [2] 3d 3f [2] 00 }

  condition:
    any of them
}