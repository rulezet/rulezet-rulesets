rule TTP_XOR_MULT_DOSStub_4739 {
  strings:
    $key_4739 = { 13 51 [2] 67 49 [2] 20 4b [2] 67 5a [2] 29 56 [2] 25 5c [2] 32 57 [2] 29 19 [2] 14 }

  condition:
    any of them
}