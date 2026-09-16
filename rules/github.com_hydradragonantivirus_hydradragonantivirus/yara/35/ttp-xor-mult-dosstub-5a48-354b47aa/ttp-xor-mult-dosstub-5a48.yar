rule TTP_XOR_MULT_DOSStub_5a48 {
  strings:
    $key_5a48 = { 0e 20 [2] 7a 38 [2] 3d 3a [2] 7a 2b [2] 34 27 [2] 38 2d [2] 2f 26 [2] 34 68 [2] 09 }

  condition:
    any of them
}