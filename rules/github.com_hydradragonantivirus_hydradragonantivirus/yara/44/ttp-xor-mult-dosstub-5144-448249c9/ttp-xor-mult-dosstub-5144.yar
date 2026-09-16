rule TTP_XOR_MULT_DOSStub_5144 {
  strings:
    $key_5144 = { 05 2c [2] 71 34 [2] 36 36 [2] 71 27 [2] 3f 2b [2] 33 21 [2] 24 2a [2] 3f 64 [2] 02 }

  condition:
    any of them
}