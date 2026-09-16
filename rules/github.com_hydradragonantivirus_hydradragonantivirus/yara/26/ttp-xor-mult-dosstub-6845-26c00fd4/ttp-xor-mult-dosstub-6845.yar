rule TTP_XOR_MULT_DOSStub_6845 {
  strings:
    $key_6845 = { 3c 2d [2] 48 35 [2] 0f 37 [2] 48 26 [2] 06 2a [2] 0a 20 [2] 1d 2b [2] 06 65 [2] 3b }

  condition:
    any of them
}