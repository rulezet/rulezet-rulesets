rule TTP_XOR_MULT_DOSStub_7433 {
  strings:
    $key_7433 = { 20 5b [2] 54 43 [2] 13 41 [2] 54 50 [2] 1a 5c [2] 16 56 [2] 01 5d [2] 1a 13 [2] 27 }

  condition:
    any of them
}