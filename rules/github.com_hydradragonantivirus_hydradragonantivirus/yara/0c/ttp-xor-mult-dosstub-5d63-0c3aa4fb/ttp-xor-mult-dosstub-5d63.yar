rule TTP_XOR_MULT_DOSStub_5d63 {
  strings:
    $key_5d63 = { 09 0b [2] 7d 13 [2] 3a 11 [2] 7d 00 [2] 33 0c [2] 3f 06 [2] 28 0d [2] 33 43 [2] 0e }

  condition:
    any of them
}