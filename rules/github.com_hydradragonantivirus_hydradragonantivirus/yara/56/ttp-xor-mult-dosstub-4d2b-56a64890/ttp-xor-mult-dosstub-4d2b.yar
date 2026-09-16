rule TTP_XOR_MULT_DOSStub_4d2b {
  strings:
    $key_4d2b = { 19 43 [2] 6d 5b [2] 2a 59 [2] 6d 48 [2] 23 44 [2] 2f 4e [2] 38 45 [2] 23 0b [2] 1e }

  condition:
    any of them
}