rule TTP_XOR_MULT_DOSStub_5177 {
  strings:
    $key_5177 = { 05 1f [2] 71 07 [2] 36 05 [2] 71 14 [2] 3f 18 [2] 33 12 [2] 24 19 [2] 3f 57 [2] 02 }

  condition:
    any of them
}