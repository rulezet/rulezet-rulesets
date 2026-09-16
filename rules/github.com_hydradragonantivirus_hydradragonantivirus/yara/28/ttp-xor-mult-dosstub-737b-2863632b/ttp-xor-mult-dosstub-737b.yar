rule TTP_XOR_MULT_DOSStub_737b {
  strings:
    $key_737b = { 27 13 [2] 53 0b [2] 14 09 [2] 53 18 [2] 1d 14 [2] 11 1e [2] 06 15 [2] 1d 5b [2] 20 }

  condition:
    any of them
}