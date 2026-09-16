rule TTP_XOR_MULT_DOSStub_6e7b {
  strings:
    $key_6e7b = { 3a 13 [2] 4e 0b [2] 09 09 [2] 4e 18 [2] 00 14 [2] 0c 1e [2] 1b 15 [2] 00 5b [2] 3d }

  condition:
    any of them
}