rule TTP_XOR_MULT_DOSStub_1555 {
  strings:
    $key_1555 = { 41 3d [2] 35 25 [2] 72 27 [2] 35 36 [2] 7b 3a [2] 77 30 [2] 60 3b [2] 7b 75 [2] 46 }

  condition:
    any of them
}