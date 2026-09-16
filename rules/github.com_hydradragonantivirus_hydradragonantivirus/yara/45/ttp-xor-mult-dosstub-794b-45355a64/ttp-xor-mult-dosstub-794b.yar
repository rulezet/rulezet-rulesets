rule TTP_XOR_MULT_DOSStub_794b {
  strings:
    $key_794b = { 2d 23 [2] 59 3b [2] 1e 39 [2] 59 28 [2] 17 24 [2] 1b 2e [2] 0c 25 [2] 17 6b [2] 2a }

  condition:
    any of them
}