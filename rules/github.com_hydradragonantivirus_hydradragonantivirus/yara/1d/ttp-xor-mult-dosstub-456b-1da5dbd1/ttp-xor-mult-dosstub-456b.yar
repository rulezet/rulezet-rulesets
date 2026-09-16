rule TTP_XOR_MULT_DOSStub_456b {
  strings:
    $key_456b = { 11 03 [2] 65 1b [2] 22 19 [2] 65 08 [2] 2b 04 [2] 27 0e [2] 30 05 [2] 2b 4b [2] 16 }

  condition:
    any of them
}