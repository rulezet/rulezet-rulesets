rule TTP_XOR_MULT_DOSStub_0e55 {
  strings:
    $key_0e55 = { 5a 3d [2] 2e 25 [2] 69 27 [2] 2e 36 [2] 60 3a [2] 6c 30 [2] 7b 3b [2] 60 75 [2] 5d }

  condition:
    any of them
}