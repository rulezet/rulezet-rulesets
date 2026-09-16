rule TTP_XOR_MULT_DOSStub_5ae5 {
  strings:
    $key_5ae5 = { 0e 8d [2] 7a 95 [2] 3d 97 [2] 7a 86 [2] 34 8a [2] 38 80 [2] 2f 8b [2] 34 c5 [2] 09 }

  condition:
    any of them
}