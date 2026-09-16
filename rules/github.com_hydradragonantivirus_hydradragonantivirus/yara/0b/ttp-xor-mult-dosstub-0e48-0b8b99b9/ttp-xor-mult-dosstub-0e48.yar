rule TTP_XOR_MULT_DOSStub_0e48 {
  strings:
    $key_0e48 = { 5a 20 [2] 2e 38 [2] 69 3a [2] 2e 2b [2] 60 27 [2] 6c 2d [2] 7b 26 [2] 60 68 [2] 5d }

  condition:
    any of them
}