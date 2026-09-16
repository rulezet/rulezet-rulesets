rule TTP_XOR_MULT_DOSStub_6733 {
  strings:
    $key_6733 = { 33 5b [2] 47 43 [2] 00 41 [2] 47 50 [2] 09 5c [2] 05 56 [2] 12 5d [2] 09 13 [2] 34 }

  condition:
    any of them
}