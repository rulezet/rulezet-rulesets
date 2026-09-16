rule TTP_XOR_MULT_DOSStub_5733 {
  strings:
    $key_5733 = { 03 5b [2] 77 43 [2] 30 41 [2] 77 50 [2] 39 5c [2] 35 56 [2] 22 5d [2] 39 13 [2] 04 }

  condition:
    any of them
}