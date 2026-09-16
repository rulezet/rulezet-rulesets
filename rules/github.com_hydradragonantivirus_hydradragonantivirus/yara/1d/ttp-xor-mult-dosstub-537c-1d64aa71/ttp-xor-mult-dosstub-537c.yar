rule TTP_XOR_MULT_DOSStub_537c {
  strings:
    $key_537c = { 07 14 [2] 73 0c [2] 34 0e [2] 73 1f [2] 3d 13 [2] 31 19 [2] 26 12 [2] 3d 5c [2] 00 }

  condition:
    any of them
}