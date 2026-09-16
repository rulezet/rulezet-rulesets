rule TTP_XOR_MULT_DOSStub_4409 {
  strings:
    $key_4409 = { 10 61 [2] 64 79 [2] 23 7b [2] 64 6a [2] 2a 66 [2] 26 6c [2] 31 67 [2] 2a 29 [2] 17 }

  condition:
    any of them
}