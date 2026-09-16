rule TTP_XOR_MULT_DOSStub_5122 {
  strings:
    $key_5122 = { 05 4a [2] 71 52 [2] 36 50 [2] 71 41 [2] 3f 4d [2] 33 47 [2] 24 4c [2] 3f 02 [2] 02 }

  condition:
    any of them
}