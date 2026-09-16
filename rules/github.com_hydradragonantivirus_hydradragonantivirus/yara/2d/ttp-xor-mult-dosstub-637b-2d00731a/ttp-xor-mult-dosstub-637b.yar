rule TTP_XOR_MULT_DOSStub_637b {
  strings:
    $key_637b = { 37 13 [2] 43 0b [2] 04 09 [2] 43 18 [2] 0d 14 [2] 01 1e [2] 16 15 [2] 0d 5b [2] 30 }

  condition:
    any of them
}