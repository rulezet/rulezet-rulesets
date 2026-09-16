rule TTP_XOR_MULT_DOSStub_787c {
  strings:
    $key_787c = { 2c 14 [2] 58 0c [2] 1f 0e [2] 58 1f [2] 16 13 [2] 1a 19 [2] 0d 12 [2] 16 5c [2] 2b }

  condition:
    any of them
}