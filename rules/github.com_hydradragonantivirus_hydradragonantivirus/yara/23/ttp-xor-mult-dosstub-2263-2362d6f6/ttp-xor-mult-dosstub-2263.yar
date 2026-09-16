rule TTP_XOR_MULT_DOSStub_2263 {
  strings:
    $key_2263 = { 76 0b [2] 02 13 [2] 45 11 [2] 02 00 [2] 4c 0c [2] 40 06 [2] 57 0d [2] 4c 43 [2] 71 }

  condition:
    any of them
}