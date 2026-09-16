rule TTP_XOR_MULT_DOSStub_7834 {
  strings:
    $key_7834 = { 2c 5c [2] 58 44 [2] 1f 46 [2] 58 57 [2] 16 5b [2] 1a 51 [2] 0d 5a [2] 16 14 [2] 2b }

  condition:
    any of them
}