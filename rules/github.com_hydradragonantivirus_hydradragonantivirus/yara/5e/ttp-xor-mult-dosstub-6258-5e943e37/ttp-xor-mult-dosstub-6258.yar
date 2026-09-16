rule TTP_XOR_MULT_DOSStub_6258 {
  strings:
    $key_6258 = { 36 30 [2] 42 28 [2] 05 2a [2] 42 3b [2] 0c 37 [2] 00 3d [2] 17 36 [2] 0c 78 [2] 31 }

  condition:
    any of them
}