rule TTP_XOR_MULT_DOSStub_0774 {
  strings:
    $key_0774 = { 53 1c [2] 27 04 [2] 60 06 [2] 27 17 [2] 69 1b [2] 65 11 [2] 72 1a [2] 69 54 [2] 54 }

  condition:
    any of them
}