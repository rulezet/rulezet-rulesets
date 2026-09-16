rule TTP_XOR_MULT_DOSStub_5a65 {
  strings:
    $key_5a65 = { 0e 0d [2] 7a 15 [2] 3d 17 [2] 7a 06 [2] 34 0a [2] 38 00 [2] 2f 0b [2] 34 45 [2] 09 }

  condition:
    any of them
}