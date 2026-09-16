rule TTP_XOR_MULT_DOSStub_7704 {
  strings:
    $key_7704 = { 23 6c [2] 57 74 [2] 10 76 [2] 57 67 [2] 19 6b [2] 15 61 [2] 02 6a [2] 19 24 [2] 24 }

  condition:
    any of them
}