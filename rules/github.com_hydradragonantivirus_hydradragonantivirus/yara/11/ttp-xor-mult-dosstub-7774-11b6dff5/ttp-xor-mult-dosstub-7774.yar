rule TTP_XOR_MULT_DOSStub_7774 {
  strings:
    $key_7774 = { 23 1c [2] 57 04 [2] 10 06 [2] 57 17 [2] 19 1b [2] 15 11 [2] 02 1a [2] 19 54 [2] 24 }

  condition:
    any of them
}