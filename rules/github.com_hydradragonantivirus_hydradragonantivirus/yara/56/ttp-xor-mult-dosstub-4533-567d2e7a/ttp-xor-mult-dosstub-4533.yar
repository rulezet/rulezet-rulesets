rule TTP_XOR_MULT_DOSStub_4533 {
  strings:
    $key_4533 = { 11 5b [2] 65 43 [2] 22 41 [2] 65 50 [2] 2b 5c [2] 27 56 [2] 30 5d [2] 2b 13 [2] 16 }

  condition:
    any of them
}