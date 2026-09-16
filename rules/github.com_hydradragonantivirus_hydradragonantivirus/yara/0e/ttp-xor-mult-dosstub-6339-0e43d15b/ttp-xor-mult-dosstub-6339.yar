rule TTP_XOR_MULT_DOSStub_6339 {
  strings:
    $key_6339 = { 37 51 [2] 43 49 [2] 04 4b [2] 43 5a [2] 0d 56 [2] 01 5c [2] 16 57 [2] 0d 19 [2] 30 }

  condition:
    any of them
}