rule TTP_XOR_MULT_DOSStub_746b {
  strings:
    $key_746b = { 20 03 [2] 54 1b [2] 13 19 [2] 54 08 [2] 1a 04 [2] 16 0e [2] 01 05 [2] 1a 4b [2] 27 }

  condition:
    any of them
}