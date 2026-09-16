rule TTP_XOR_MULT_DOSStub_5150 {
  strings:
    $key_5150 = { 05 38 [2] 71 20 [2] 36 22 [2] 71 33 [2] 3f 3f [2] 33 35 [2] 24 3e [2] 3f 70 [2] 02 }

  condition:
    any of them
}