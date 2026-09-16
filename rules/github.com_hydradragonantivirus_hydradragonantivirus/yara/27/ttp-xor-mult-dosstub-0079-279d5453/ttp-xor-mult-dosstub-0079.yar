rule TTP_XOR_MULT_DOSStub_0079 {
  strings:
    $key_0079 = { 54 11 [2] 20 09 [2] 67 0b [2] 20 1a [2] 6e 16 [2] 62 1c [2] 75 17 [2] 6e 59 [2] 53 }

  condition:
    any of them
}