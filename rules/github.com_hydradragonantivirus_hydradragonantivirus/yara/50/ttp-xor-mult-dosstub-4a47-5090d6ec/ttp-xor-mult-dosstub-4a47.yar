rule TTP_XOR_MULT_DOSStub_4a47 {
  strings:
    $key_4a47 = { 1e 2f [2] 6a 37 [2] 2d 35 [2] 6a 24 [2] 24 28 [2] 28 22 [2] 3f 29 [2] 24 67 [2] 19 }

  condition:
    any of them
}