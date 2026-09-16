rule TTP_XOR_MULT_DOSStub_3734 {
  strings:
    $key_3734 = { 63 5c [2] 17 44 [2] 50 46 [2] 17 57 [2] 59 5b [2] 55 51 [2] 42 5a [2] 59 14 [2] 64 }

  condition:
    any of them
}