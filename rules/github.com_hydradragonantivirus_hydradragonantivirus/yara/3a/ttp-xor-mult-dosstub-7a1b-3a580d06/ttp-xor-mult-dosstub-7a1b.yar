rule TTP_XOR_MULT_DOSStub_7a1b {
  strings:
    $key_7a1b = { 2e 73 [2] 5a 6b [2] 1d 69 [2] 5a 78 [2] 14 74 [2] 18 7e [2] 0f 75 [2] 14 3b [2] 29 }

  condition:
    any of them
}