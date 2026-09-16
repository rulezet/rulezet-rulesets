rule TTP_XOR_MULT_DOSStub_2a43 {
  strings:
    $key_2a43 = { 7e 2b [2] 0a 33 [2] 4d 31 [2] 0a 20 [2] 44 2c [2] 48 26 [2] 5f 2d [2] 44 63 [2] 79 }

  condition:
    any of them
}