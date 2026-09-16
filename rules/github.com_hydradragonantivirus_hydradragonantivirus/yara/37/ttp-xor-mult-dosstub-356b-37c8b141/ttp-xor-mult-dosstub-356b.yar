rule TTP_XOR_MULT_DOSStub_356b {
  strings:
    $key_356b = { 61 03 [2] 15 1b [2] 52 19 [2] 15 08 [2] 5b 04 [2] 57 0e [2] 40 05 [2] 5b 4b [2] 66 }

  condition:
    any of them
}