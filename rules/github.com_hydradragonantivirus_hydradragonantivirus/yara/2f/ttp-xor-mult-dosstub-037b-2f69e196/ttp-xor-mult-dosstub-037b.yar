rule TTP_XOR_MULT_DOSStub_037b {
  strings:
    $key_037b = { 57 13 [2] 23 0b [2] 64 09 [2] 23 18 [2] 6d 14 [2] 61 1e [2] 76 15 [2] 6d 5b [2] 50 }

  condition:
    any of them
}