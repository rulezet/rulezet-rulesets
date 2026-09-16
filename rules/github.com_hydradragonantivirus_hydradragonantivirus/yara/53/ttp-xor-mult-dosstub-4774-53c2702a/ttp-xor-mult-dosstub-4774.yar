rule TTP_XOR_MULT_DOSStub_4774 {
  strings:
    $key_4774 = { 13 1c [2] 67 04 [2] 20 06 [2] 67 17 [2] 29 1b [2] 25 11 [2] 32 1a [2] 29 54 [2] 14 }

  condition:
    any of them
}