rule TTP_XOR_MULT_DOSStub_4e29 {
  strings:
    $key_4e29 = { 1a 41 [2] 6e 59 [2] 29 5b [2] 6e 4a [2] 20 46 [2] 2c 4c [2] 3b 47 [2] 20 09 [2] 1d }

  condition:
    any of them
}