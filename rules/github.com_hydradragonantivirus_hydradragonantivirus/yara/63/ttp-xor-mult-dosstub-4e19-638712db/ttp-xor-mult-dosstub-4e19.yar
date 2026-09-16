rule TTP_XOR_MULT_DOSStub_4e19 {
  strings:
    $key_4e19 = { 1a 71 [2] 6e 69 [2] 29 6b [2] 6e 7a [2] 20 76 [2] 2c 7c [2] 3b 77 [2] 20 39 [2] 1d }

  condition:
    any of them
}