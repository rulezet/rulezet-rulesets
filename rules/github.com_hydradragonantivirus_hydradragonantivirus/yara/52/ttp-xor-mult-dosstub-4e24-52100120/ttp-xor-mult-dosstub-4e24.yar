rule TTP_XOR_MULT_DOSStub_4e24 {
  strings:
    $key_4e24 = { 1a 4c [2] 6e 54 [2] 29 56 [2] 6e 47 [2] 20 4b [2] 2c 41 [2] 3b 4a [2] 20 04 [2] 1d }

  condition:
    any of them
}