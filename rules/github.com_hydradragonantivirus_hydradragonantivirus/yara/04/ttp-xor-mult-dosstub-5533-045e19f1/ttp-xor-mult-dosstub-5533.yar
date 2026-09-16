rule TTP_XOR_MULT_DOSStub_5533 {
  strings:
    $key_5533 = { 01 5b [2] 75 43 [2] 32 41 [2] 75 50 [2] 3b 5c [2] 37 56 [2] 20 5d [2] 3b 13 [2] 06 }

  condition:
    any of them
}