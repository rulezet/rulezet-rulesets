rule TTP_XOR_MULT_DOSStub_5e58 {
  strings:
    $key_5e58 = { 0a 30 [2] 7e 28 [2] 39 2a [2] 7e 3b [2] 30 37 [2] 3c 3d [2] 2b 36 [2] 30 78 [2] 0d }

  condition:
    any of them
}