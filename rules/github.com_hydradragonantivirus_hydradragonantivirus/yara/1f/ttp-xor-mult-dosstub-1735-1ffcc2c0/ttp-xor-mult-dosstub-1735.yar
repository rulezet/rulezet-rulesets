rule TTP_XOR_MULT_DOSStub_1735 {
  strings:
    $key_1735 = { 43 5d [2] 37 45 [2] 70 47 [2] 37 56 [2] 79 5a [2] 75 50 [2] 62 5b [2] 79 15 [2] 44 }

  condition:
    any of them
}