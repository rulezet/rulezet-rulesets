rule TTP_XOR_MULT_DOSStub_4a60 {
  strings:
    $key_4a60 = { 1e 08 [2] 6a 10 [2] 2d 12 [2] 6a 03 [2] 24 0f [2] 28 05 [2] 3f 0e [2] 24 40 [2] 19 }

  condition:
    any of them
}