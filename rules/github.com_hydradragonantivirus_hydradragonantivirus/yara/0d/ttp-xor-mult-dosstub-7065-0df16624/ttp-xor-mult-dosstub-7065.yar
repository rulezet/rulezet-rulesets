rule TTP_XOR_MULT_DOSStub_7065 {
  strings:
    $key_7065 = { 24 0d [2] 50 15 [2] 17 17 [2] 50 06 [2] 1e 0a [2] 12 00 [2] 05 0b [2] 1e 45 [2] 23 }

  condition:
    any of them
}