rule TTP_XOR_MULT_DOSStub_6745 {
  strings:
    $key_6745 = { 33 2d [2] 47 35 [2] 00 37 [2] 47 26 [2] 09 2a [2] 05 20 [2] 12 2b [2] 09 65 [2] 34 }

  condition:
    any of them
}