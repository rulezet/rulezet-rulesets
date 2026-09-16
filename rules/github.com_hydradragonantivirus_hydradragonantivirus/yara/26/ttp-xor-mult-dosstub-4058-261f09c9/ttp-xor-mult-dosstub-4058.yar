rule TTP_XOR_MULT_DOSStub_4058 {
  strings:
    $key_4058 = { 14 30 [2] 60 28 [2] 27 2a [2] 60 3b [2] 2e 37 [2] 22 3d [2] 35 36 [2] 2e 78 [2] 13 }

  condition:
    any of them
}