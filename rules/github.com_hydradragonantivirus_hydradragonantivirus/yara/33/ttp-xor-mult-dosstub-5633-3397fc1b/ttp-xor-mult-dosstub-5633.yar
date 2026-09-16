rule TTP_XOR_MULT_DOSStub_5633 {
  strings:
    $key_5633 = { 02 5b [2] 76 43 [2] 31 41 [2] 76 50 [2] 38 5c [2] 34 56 [2] 23 5d [2] 38 13 [2] 05 }

  condition:
    any of them
}