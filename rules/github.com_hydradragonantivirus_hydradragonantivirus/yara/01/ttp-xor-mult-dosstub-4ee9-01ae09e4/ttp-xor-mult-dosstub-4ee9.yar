rule TTP_XOR_MULT_DOSStub_4ee9 {
  strings:
    $key_4ee9 = { 1a 81 [2] 6e 99 [2] 29 9b [2] 6e 8a [2] 20 86 [2] 2c 8c [2] 3b 87 [2] 20 c9 [2] 1d }

  condition:
    any of them
}