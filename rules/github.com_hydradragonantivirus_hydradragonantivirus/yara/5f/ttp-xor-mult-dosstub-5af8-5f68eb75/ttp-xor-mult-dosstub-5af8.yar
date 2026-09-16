rule TTP_XOR_MULT_DOSStub_5af8 {
  strings:
    $key_5af8 = { 0e 90 [2] 7a 88 [2] 3d 8a [2] 7a 9b [2] 34 97 [2] 38 9d [2] 2f 96 [2] 34 d8 [2] 09 }

  condition:
    any of them
}