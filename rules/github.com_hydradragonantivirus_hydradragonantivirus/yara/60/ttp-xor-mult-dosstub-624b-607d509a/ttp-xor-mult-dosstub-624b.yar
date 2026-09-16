rule TTP_XOR_MULT_DOSStub_624b {
  strings:
    $key_624b = { 36 23 [2] 42 3b [2] 05 39 [2] 42 28 [2] 0c 24 [2] 00 2e [2] 17 25 [2] 0c 6b [2] 31 }

  condition:
    any of them
}