rule TTP_XOR_MULT_DOSStub_1078 {
  strings:
    $key_1078 = { 44 10 [2] 30 08 [2] 77 0a [2] 30 1b [2] 7e 17 [2] 72 1d [2] 65 16 [2] 7e 58 [2] 43 }

  condition:
    any of them
}