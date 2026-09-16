rule TTP_XOR_MULT_DOSStub_4d5b {
  strings:
    $key_4d5b = { 19 33 [2] 6d 2b [2] 2a 29 [2] 6d 38 [2] 23 34 [2] 2f 3e [2] 38 35 [2] 23 7b [2] 1e }

  condition:
    any of them
}