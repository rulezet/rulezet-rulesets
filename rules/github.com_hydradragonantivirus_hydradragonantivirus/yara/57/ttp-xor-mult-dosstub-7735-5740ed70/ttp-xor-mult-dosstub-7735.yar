rule TTP_XOR_MULT_DOSStub_7735 {
  strings:
    $key_7735 = { 23 5d [2] 57 45 [2] 10 47 [2] 57 56 [2] 19 5a [2] 15 50 [2] 02 5b [2] 19 15 [2] 24 }

  condition:
    any of them
}