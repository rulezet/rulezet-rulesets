rule TTP_XOR_MULT_DOSStub_707b {
  strings:
    $key_707b = { 24 13 [2] 50 0b [2] 17 09 [2] 50 18 [2] 1e 14 [2] 12 1e [2] 05 15 [2] 1e 5b [2] 23 }

  condition:
    any of them
}