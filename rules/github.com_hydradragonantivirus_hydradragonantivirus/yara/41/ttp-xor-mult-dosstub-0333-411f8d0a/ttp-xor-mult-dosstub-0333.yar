rule TTP_XOR_MULT_DOSStub_0333 {
  strings:
    $key_0333 = { 57 5b [2] 23 43 [2] 64 41 [2] 23 50 [2] 6d 5c [2] 61 56 [2] 76 5d [2] 6d 13 [2] 50 }

  condition:
    any of them
}