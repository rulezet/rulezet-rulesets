rule TTP_XOR_MULT_DOSStub_477b {
  strings:
    $key_477b = { 13 13 [2] 67 0b [2] 20 09 [2] 67 18 [2] 29 14 [2] 25 1e [2] 32 15 [2] 29 5b [2] 14 }

  condition:
    any of them
}