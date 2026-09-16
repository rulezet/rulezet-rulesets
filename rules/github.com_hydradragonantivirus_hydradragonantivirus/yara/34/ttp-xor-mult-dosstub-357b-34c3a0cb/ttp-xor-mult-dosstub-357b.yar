rule TTP_XOR_MULT_DOSStub_357b {
  strings:
    $key_357b = { 61 13 [2] 15 0b [2] 52 09 [2] 15 18 [2] 5b 14 [2] 57 1e [2] 40 15 [2] 5b 5b [2] 66 }

  condition:
    any of them
}