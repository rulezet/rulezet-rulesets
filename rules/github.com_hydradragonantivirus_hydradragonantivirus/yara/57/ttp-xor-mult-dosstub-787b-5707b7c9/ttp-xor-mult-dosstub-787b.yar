rule TTP_XOR_MULT_DOSStub_787b {
  strings:
    $key_787b = { 2c 13 [2] 58 0b [2] 1f 09 [2] 58 18 [2] 16 14 [2] 1a 1e [2] 0d 15 [2] 16 5b [2] 2b }

  condition:
    any of them
}