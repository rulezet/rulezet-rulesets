rule TTP_XOR_MULT_DOSStub_5a22 {
  strings:
    $key_5a22 = { 0e 4a [2] 7a 52 [2] 3d 50 [2] 7a 41 [2] 34 4d [2] 38 47 [2] 2f 4c [2] 34 02 [2] 09 }

  condition:
    any of them
}