rule TTP_XOR_MULT_DOSStub_4d6b {
  strings:
    $key_4d6b = { 19 03 [2] 6d 1b [2] 2a 19 [2] 6d 08 [2] 23 04 [2] 2f 0e [2] 38 05 [2] 23 4b [2] 1e }

  condition:
    any of them
}