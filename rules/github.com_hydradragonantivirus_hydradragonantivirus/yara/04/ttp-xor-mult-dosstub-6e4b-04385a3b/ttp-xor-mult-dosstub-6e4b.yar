rule TTP_XOR_MULT_DOSStub_6e4b {
  strings:
    $key_6e4b = { 3a 23 [2] 4e 3b [2] 09 39 [2] 4e 28 [2] 00 24 [2] 0c 2e [2] 1b 25 [2] 00 6b [2] 3d }

  condition:
    any of them
}