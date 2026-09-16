rule TTP_XOR_MULT_DOSStub_5a60 {
  strings:
    $key_5a60 = { 0e 08 [2] 7a 10 [2] 3d 12 [2] 7a 03 [2] 34 0f [2] 38 05 [2] 2f 0e [2] 34 40 [2] 09 }

  condition:
    any of them
}