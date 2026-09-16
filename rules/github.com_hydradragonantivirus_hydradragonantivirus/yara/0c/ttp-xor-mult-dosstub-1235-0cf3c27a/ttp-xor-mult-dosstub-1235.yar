rule TTP_XOR_MULT_DOSStub_1235 {
  strings:
    $key_1235 = { 46 5d [2] 32 45 [2] 75 47 [2] 32 56 [2] 7c 5a [2] 70 50 [2] 67 5b [2] 7c 15 [2] 41 }

  condition:
    any of them
}