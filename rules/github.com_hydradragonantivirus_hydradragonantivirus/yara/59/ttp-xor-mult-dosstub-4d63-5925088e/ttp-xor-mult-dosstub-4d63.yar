rule TTP_XOR_MULT_DOSStub_4d63 {
  strings:
    $key_4d63 = { 19 0b [2] 6d 13 [2] 2a 11 [2] 6d 00 [2] 23 0c [2] 2f 06 [2] 38 0d [2] 23 43 [2] 1e }

  condition:
    any of them
}