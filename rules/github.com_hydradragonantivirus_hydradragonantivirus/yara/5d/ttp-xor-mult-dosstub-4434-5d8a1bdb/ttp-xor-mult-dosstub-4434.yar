rule TTP_XOR_MULT_DOSStub_4434 {
  strings:
    $key_4434 = { 10 5c [2] 64 44 [2] 23 46 [2] 64 57 [2] 2a 5b [2] 26 51 [2] 31 5a [2] 2a 14 [2] 17 }

  condition:
    any of them
}