rule TTP_XOR_MULT_DOSStub_743b {
  strings:
    $key_743b = { 20 53 [2] 54 4b [2] 13 49 [2] 54 58 [2] 1a 54 [2] 16 5e [2] 01 55 [2] 1a 1b [2] 27 }

  condition:
    any of them
}