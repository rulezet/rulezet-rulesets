rule TTP_XOR_MULT_DOSStub_5af7 {
  strings:
    $key_5af7 = { 0e 9f [2] 7a 87 [2] 3d 85 [2] 7a 94 [2] 34 98 [2] 38 92 [2] 2f 99 [2] 34 d7 [2] 09 }

  condition:
    any of them
}