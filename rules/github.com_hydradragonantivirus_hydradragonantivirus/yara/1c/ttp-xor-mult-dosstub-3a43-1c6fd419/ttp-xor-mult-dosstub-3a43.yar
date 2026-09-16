rule TTP_XOR_MULT_DOSStub_3a43 {
  strings:
    $key_3a43 = { 6e 2b [2] 1a 33 [2] 5d 31 [2] 1a 20 [2] 54 2c [2] 58 26 [2] 4f 2d [2] 54 63 [2] 69 }

  condition:
    any of them
}