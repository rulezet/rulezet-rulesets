rule TTP_XOR_MULT_DOSStub_6434 {
  strings:
    $key_6434 = { 30 5c [2] 44 44 [2] 03 46 [2] 44 57 [2] 0a 5b [2] 06 51 [2] 11 5a [2] 0a 14 [2] 37 }

  condition:
    any of them
}