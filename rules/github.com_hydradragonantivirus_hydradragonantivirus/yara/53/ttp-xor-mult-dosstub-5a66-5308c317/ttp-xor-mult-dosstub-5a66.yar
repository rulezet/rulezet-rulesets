rule TTP_XOR_MULT_DOSStub_5a66 {
  strings:
    $key_5a66 = { 0e 0e [2] 7a 16 [2] 3d 14 [2] 7a 05 [2] 34 09 [2] 38 03 [2] 2f 08 [2] 34 46 [2] 09 }

  condition:
    any of them
}