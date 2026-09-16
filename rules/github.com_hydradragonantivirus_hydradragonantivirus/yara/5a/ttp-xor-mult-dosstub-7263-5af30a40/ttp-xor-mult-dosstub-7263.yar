rule TTP_XOR_MULT_DOSStub_7263 {
  strings:
    $key_7263 = { 26 0b [2] 52 13 [2] 15 11 [2] 52 00 [2] 1c 0c [2] 10 06 [2] 07 0d [2] 1c 43 [2] 21 }

  condition:
    any of them
}