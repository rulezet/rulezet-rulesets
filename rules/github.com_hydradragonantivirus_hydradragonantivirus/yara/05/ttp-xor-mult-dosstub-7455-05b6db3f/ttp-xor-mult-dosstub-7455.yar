rule TTP_XOR_MULT_DOSStub_7455 {
  strings:
    $key_7455 = { 20 3d [2] 54 25 [2] 13 27 [2] 54 36 [2] 1a 3a [2] 16 30 [2] 01 3b [2] 1a 75 [2] 27 }

  condition:
    any of them
}