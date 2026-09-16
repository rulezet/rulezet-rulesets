rule TTP_XOR_MULT_DOSStub_0e58 {
  strings:
    $key_0e58 = { 5a 30 [2] 2e 28 [2] 69 2a [2] 2e 3b [2] 60 37 [2] 6c 3d [2] 7b 36 [2] 60 78 [2] 5d }

  condition:
    any of them
}