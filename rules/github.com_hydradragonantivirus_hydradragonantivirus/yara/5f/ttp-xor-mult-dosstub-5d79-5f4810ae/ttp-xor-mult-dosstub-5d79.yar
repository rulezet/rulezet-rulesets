rule TTP_XOR_MULT_DOSStub_5d79 {
  strings:
    $key_5d79 = { 09 11 [2] 7d 09 [2] 3a 0b [2] 7d 1a [2] 33 16 [2] 3f 1c [2] 28 17 [2] 33 59 [2] 0e }

  condition:
    any of them
}