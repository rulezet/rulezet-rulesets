rule TTP_XOR_MULT_DOSStub_4e79 {
  strings:
    $key_4e79 = { 1a 11 [2] 6e 09 [2] 29 0b [2] 6e 1a [2] 20 16 [2] 2c 1c [2] 3b 17 [2] 20 59 [2] 1d }

  condition:
    any of them
}