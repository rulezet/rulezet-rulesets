rule TTP_XOR_MULT_DOSStub_0063 {
  strings:
    $key_0063 = { 54 0b [2] 20 13 [2] 67 11 [2] 20 00 [2] 6e 0c [2] 62 06 [2] 75 0d [2] 6e 43 [2] 53 }

  condition:
    any of them
}