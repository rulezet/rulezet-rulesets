rule TTP_XOR_MULT_DOSStub_7739 {
  strings:
    $key_7739 = { 23 51 [2] 57 49 [2] 10 4b [2] 57 5a [2] 19 56 [2] 15 5c [2] 02 57 [2] 19 19 [2] 24 }

  condition:
    any of them
}