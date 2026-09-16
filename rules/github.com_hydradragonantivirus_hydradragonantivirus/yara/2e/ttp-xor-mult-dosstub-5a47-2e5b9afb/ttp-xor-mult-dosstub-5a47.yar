rule TTP_XOR_MULT_DOSStub_5a47 {
  strings:
    $key_5a47 = { 0e 2f [2] 7a 37 [2] 3d 35 [2] 7a 24 [2] 34 28 [2] 38 22 [2] 2f 29 [2] 34 67 [2] 09 }

  condition:
    any of them
}