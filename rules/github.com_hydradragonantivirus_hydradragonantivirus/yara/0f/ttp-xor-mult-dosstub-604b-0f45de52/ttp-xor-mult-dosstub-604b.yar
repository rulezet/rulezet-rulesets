rule TTP_XOR_MULT_DOSStub_604b {
  strings:
    $key_604b = { 34 23 [2] 40 3b [2] 07 39 [2] 40 28 [2] 0e 24 [2] 02 2e [2] 15 25 [2] 0e 6b [2] 33 }

  condition:
    any of them
}