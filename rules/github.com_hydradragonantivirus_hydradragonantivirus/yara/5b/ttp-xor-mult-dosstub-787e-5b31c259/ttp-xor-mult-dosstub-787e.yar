rule TTP_XOR_MULT_DOSStub_787e {
  strings:
    $key_787e = { 2c 16 [2] 58 0e [2] 1f 0c [2] 58 1d [2] 16 11 [2] 1a 1b [2] 0d 10 [2] 16 5e [2] 2b }

  condition:
    any of them
}