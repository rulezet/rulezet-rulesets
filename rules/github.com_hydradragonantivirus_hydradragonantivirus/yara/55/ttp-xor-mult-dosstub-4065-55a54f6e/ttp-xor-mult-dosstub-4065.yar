rule TTP_XOR_MULT_DOSStub_4065 {
  strings:
    $key_4065 = { 14 0d [2] 60 15 [2] 27 17 [2] 60 06 [2] 2e 0a [2] 22 00 [2] 35 0b [2] 2e 45 [2] 13 }

  condition:
    any of them
}