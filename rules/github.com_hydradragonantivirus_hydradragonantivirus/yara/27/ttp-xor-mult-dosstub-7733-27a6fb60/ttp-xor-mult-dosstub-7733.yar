rule TTP_XOR_MULT_DOSStub_7733 {
  strings:
    $key_7733 = { 23 5b [2] 57 43 [2] 10 41 [2] 57 50 [2] 19 5c [2] 15 56 [2] 02 5d [2] 19 13 [2] 24 }

  condition:
    any of them
}