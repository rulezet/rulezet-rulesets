rule TTP_XOR_MULT_DOSStub_5af5 {
  strings:
    $key_5af5 = { 0e 9d [2] 7a 85 [2] 3d 87 [2] 7a 96 [2] 34 9a [2] 38 90 [2] 2f 9b [2] 34 d5 [2] 09 }

  condition:
    any of them
}