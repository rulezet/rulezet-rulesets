rule TTP_XOR_MULT_DOSStub_366b {
  strings:
    $key_366b = { 62 03 [2] 16 1b [2] 51 19 [2] 16 08 [2] 58 04 [2] 54 0e [2] 43 05 [2] 58 4b [2] 65 }

  condition:
    any of them
}