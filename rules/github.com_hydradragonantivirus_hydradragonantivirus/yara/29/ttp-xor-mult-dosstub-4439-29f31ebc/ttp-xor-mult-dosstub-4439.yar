rule TTP_XOR_MULT_DOSStub_4439 {
  strings:
    $key_4439 = { 10 51 [2] 64 49 [2] 23 4b [2] 64 5a [2] 2a 56 [2] 26 5c [2] 31 57 [2] 2a 19 [2] 17 }

  condition:
    any of them
}