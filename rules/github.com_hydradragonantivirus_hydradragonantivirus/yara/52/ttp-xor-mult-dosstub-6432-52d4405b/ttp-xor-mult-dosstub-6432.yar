rule TTP_XOR_MULT_DOSStub_6432 {
  strings:
    $key_6432 = { 30 5a [2] 44 42 [2] 03 40 [2] 44 51 [2] 0a 5d [2] 06 57 [2] 11 5c [2] 0a 12 [2] 37 }

  condition:
    any of them
}