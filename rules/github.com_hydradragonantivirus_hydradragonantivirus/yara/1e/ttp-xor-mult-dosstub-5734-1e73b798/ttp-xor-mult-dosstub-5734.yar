rule TTP_XOR_MULT_DOSStub_5734 {
  strings:
    $key_5734 = { 03 5c [2] 77 44 [2] 30 46 [2] 77 57 [2] 39 5b [2] 35 51 [2] 22 5a [2] 39 14 [2] 04 }

  condition:
    any of them
}