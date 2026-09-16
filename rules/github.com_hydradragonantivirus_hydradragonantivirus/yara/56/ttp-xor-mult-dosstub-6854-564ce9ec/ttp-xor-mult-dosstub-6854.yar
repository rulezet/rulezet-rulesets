rule TTP_XOR_MULT_DOSStub_6854 {
  strings:
    $key_6854 = { 3c 3c [2] 48 24 [2] 0f 26 [2] 48 37 [2] 06 3b [2] 0a 31 [2] 1d 3a [2] 06 74 [2] 3b }

  condition:
    any of them
}