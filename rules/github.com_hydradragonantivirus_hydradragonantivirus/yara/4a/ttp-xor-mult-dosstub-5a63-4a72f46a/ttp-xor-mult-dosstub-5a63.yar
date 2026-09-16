rule TTP_XOR_MULT_DOSStub_5a63 {
  strings:
    $key_5a63 = { 0e 0b [2] 7a 13 [2] 3d 11 [2] 7a 00 [2] 34 0c [2] 38 06 [2] 2f 0d [2] 34 43 [2] 09 }

  condition:
    any of them
}