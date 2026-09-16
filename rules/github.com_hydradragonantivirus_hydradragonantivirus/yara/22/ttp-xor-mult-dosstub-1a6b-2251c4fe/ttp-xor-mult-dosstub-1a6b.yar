rule TTP_XOR_MULT_DOSStub_1a6b {
  strings:
    $key_1a6b = { 4e 03 [2] 3a 1b [2] 7d 19 [2] 3a 08 [2] 74 04 [2] 78 0e [2] 6f 05 [2] 74 4b [2] 49 }

  condition:
    any of them
}