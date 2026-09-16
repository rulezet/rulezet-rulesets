rule TTP_XOR_MULT_DOSStub_5166 {
  strings:
    $key_5166 = { 05 0e [2] 71 16 [2] 36 14 [2] 71 05 [2] 3f 09 [2] 33 03 [2] 24 08 [2] 3f 46 [2] 02 }

  condition:
    any of them
}