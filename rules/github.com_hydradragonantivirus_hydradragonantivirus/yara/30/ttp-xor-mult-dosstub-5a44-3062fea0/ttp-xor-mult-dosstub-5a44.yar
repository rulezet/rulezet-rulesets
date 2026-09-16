rule TTP_XOR_MULT_DOSStub_5a44 {
  strings:
    $key_5a44 = { 0e 2c [2] 7a 34 [2] 3d 36 [2] 7a 27 [2] 34 2b [2] 38 21 [2] 2f 2a [2] 34 64 [2] 09 }

  condition:
    any of them
}