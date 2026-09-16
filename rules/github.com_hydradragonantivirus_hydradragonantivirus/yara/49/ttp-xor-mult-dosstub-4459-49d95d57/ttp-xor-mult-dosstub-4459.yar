rule TTP_XOR_MULT_DOSStub_4459 {
  strings:
    $key_4459 = { 10 31 [2] 64 29 [2] 23 2b [2] 64 3a [2] 2a 36 [2] 26 3c [2] 31 37 [2] 2a 79 [2] 17 }

  condition:
    any of them
}