rule TTP_XOR_MULT_DOSStub_4e14 {
  strings:
    $key_4e14 = { 1a 7c [2] 6e 64 [2] 29 66 [2] 6e 77 [2] 20 7b [2] 2c 71 [2] 3b 7a [2] 20 34 [2] 1d }

  condition:
    any of them
}