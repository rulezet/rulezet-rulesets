rule TTP_XOR_MULT_DOSStub_3474 {
  strings:
    $key_3474 = { 60 1c [2] 14 04 [2] 53 06 [2] 14 17 [2] 5a 1b [2] 56 11 [2] 41 1a [2] 5a 54 [2] 67 }

  condition:
    any of them
}