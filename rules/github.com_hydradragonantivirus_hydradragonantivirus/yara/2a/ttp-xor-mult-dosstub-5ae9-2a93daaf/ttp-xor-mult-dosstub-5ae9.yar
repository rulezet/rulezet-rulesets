rule TTP_XOR_MULT_DOSStub_5ae9 {
  strings:
    $key_5ae9 = { 0e 81 [2] 7a 99 [2] 3d 9b [2] 7a 8a [2] 34 86 [2] 38 8c [2] 2f 87 [2] 34 c9 [2] 09 }

  condition:
    any of them
}