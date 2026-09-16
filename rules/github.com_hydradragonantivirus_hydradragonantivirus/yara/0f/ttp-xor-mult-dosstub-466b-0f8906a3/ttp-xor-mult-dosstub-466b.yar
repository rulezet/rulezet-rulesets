rule TTP_XOR_MULT_DOSStub_466b {
  strings:
    $key_466b = { 12 03 [2] 66 1b [2] 21 19 [2] 66 08 [2] 28 04 [2] 24 0e [2] 33 05 [2] 28 4b [2] 15 }

  condition:
    any of them
}