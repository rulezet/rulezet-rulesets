rule TTP_XOR_MULT_DOSStub_6455 {
  strings:
    $key_6455 = { 30 3d [2] 44 25 [2] 03 27 [2] 44 36 [2] 0a 3a [2] 06 30 [2] 11 3b [2] 0a 75 [2] 37 }

  condition:
    any of them
}