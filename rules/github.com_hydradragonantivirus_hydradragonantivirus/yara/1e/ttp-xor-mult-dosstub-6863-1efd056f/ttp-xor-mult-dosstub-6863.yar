rule TTP_XOR_MULT_DOSStub_6863 {
  strings:
    $key_6863 = { 3c 0b [2] 48 13 [2] 0f 11 [2] 48 00 [2] 06 0c [2] 0a 06 [2] 1d 0d [2] 06 43 [2] 3b }

  condition:
    any of them
}