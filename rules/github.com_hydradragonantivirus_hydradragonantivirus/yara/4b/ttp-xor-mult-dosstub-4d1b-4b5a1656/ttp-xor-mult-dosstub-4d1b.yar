rule TTP_XOR_MULT_DOSStub_4d1b {
  strings:
    $key_4d1b = { 19 73 [2] 6d 6b [2] 2a 69 [2] 6d 78 [2] 23 74 [2] 2f 7e [2] 38 75 [2] 23 3b [2] 1e }

  condition:
    any of them
}