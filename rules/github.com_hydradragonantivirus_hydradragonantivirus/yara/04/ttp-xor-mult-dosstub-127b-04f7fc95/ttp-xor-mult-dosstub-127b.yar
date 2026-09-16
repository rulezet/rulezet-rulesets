rule TTP_XOR_MULT_DOSStub_127b {
  strings:
    $key_127b = { 46 13 [2] 32 0b [2] 75 09 [2] 32 18 [2] 7c 14 [2] 70 1e [2] 67 15 [2] 7c 5b [2] 41 }

  condition:
    any of them
}