rule TTP_XOR_MULT_DOSStub_036b {
  strings:
    $key_036b = { 57 03 [2] 23 1b [2] 64 19 [2] 23 08 [2] 6d 04 [2] 61 0e [2] 76 05 [2] 6d 4b [2] 50 }

  condition:
    any of them
}