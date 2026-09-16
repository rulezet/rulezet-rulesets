rule TTP_XOR_MULT_DOSStub_5ae4 {
  strings:
    $key_5ae4 = { 0e 8c [2] 7a 94 [2] 3d 96 [2] 7a 87 [2] 34 8b [2] 38 81 [2] 2f 8a [2] 34 c4 [2] 09 }

  condition:
    any of them
}