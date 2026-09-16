rule TTP_XOR_MULT_DOSStub_2279 {
  strings:
    $key_2279 = { 76 11 [2] 02 09 [2] 45 0b [2] 02 1a [2] 4c 16 [2] 40 1c [2] 57 17 [2] 4c 59 [2] 71 }

  condition:
    any of them
}