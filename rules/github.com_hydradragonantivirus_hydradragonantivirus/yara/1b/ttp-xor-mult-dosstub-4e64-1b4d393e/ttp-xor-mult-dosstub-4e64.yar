rule TTP_XOR_MULT_DOSStub_4e64 {
  strings:
    $key_4e64 = { 1a 0c [2] 6e 14 [2] 29 16 [2] 6e 07 [2] 20 0b [2] 2c 01 [2] 3b 0a [2] 20 44 [2] 1d }

  condition:
    any of them
}