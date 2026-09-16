rule TTP_XOR_MULT_DOSStub_7553 {
  strings:
    $key_7553 = { 21 3b [2] 55 23 [2] 12 21 [2] 55 30 [2] 1b 3c [2] 17 36 [2] 00 3d [2] 1b 73 [2] 26 }

  condition:
    any of them
}