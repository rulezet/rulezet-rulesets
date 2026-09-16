rule TTP_XOR_MULT_DOSStub_5739 {
  strings:
    $key_5739 = { 03 51 [2] 77 49 [2] 30 4b [2] 77 5a [2] 39 56 [2] 35 5c [2] 22 57 [2] 39 19 [2] 04 }

  condition:
    any of them
}