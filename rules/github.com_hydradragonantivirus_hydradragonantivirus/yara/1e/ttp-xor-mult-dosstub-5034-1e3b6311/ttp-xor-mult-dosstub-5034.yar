rule TTP_XOR_MULT_DOSStub_5034 {
  strings:
    $key_5034 = { 04 5c [2] 70 44 [2] 37 46 [2] 70 57 [2] 3e 5b [2] 32 51 [2] 25 5a [2] 3e 14 [2] 03 }

  condition:
    any of them
}