rule TTP_XOR_MULT_DOSStub_6843 {
  strings:
    $key_6843 = { 3c 2b [2] 48 33 [2] 0f 31 [2] 48 20 [2] 06 2c [2] 0a 26 [2] 1d 2d [2] 06 63 [2] 3b }

  condition:
    any of them
}