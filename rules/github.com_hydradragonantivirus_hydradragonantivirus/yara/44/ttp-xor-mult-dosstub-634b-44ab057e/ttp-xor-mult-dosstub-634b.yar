rule TTP_XOR_MULT_DOSStub_634b {
  strings:
    $key_634b = { 37 23 [2] 43 3b [2] 04 39 [2] 43 28 [2] 0d 24 [2] 01 2e [2] 16 25 [2] 0d 6b [2] 30 }

  condition:
    any of them
}