rule TTP_XOR_MULT_DOSStub_7734 {
  strings:
    $key_7734 = { 23 5c [2] 57 44 [2] 10 46 [2] 57 57 [2] 19 5b [2] 15 51 [2] 02 5a [2] 19 14 [2] 24 }

  condition:
    any of them
}