rule TTP_XOR_MULT_DOSStub_1455 {
  strings:
    $key_1455 = { 40 3d [2] 34 25 [2] 73 27 [2] 34 36 [2] 7a 3a [2] 76 30 [2] 61 3b [2] 7a 75 [2] 47 }

  condition:
    any of them
}