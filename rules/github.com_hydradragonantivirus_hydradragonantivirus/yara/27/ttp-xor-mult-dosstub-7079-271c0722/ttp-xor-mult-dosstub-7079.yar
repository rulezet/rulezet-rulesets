rule TTP_XOR_MULT_DOSStub_7079 {
  strings:
    $key_7079 = { 24 11 [2] 50 09 [2] 17 0b [2] 50 1a [2] 1e 16 [2] 12 1c [2] 05 17 [2] 1e 59 [2] 23 }

  condition:
    any of them
}