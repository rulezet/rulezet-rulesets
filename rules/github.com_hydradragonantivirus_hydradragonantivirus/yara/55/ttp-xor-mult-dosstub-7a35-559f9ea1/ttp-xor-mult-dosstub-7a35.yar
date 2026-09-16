rule TTP_XOR_MULT_DOSStub_7a35 {
  strings:
    $key_7a35 = { 2e 5d [2] 5a 45 [2] 1d 47 [2] 5a 56 [2] 14 5a [2] 18 50 [2] 0f 5b [2] 14 15 [2] 29 }

  condition:
    any of them
}