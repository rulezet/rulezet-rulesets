rule TTP_XOR_MULT_DOSStub_437b {
  strings:
    $key_437b = { 17 13 [2] 63 0b [2] 24 09 [2] 63 18 [2] 2d 14 [2] 21 1e [2] 36 15 [2] 2d 5b [2] 10 }

  condition:
    any of them
}