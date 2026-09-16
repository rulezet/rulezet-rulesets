rule TTP_XOR_MULT_DOSStub_387b {
  strings:
    $key_387b = { 6c 13 [2] 18 0b [2] 5f 09 [2] 18 18 [2] 56 14 [2] 5a 1e [2] 4d 15 [2] 56 5b [2] 6b }

  condition:
    any of them
}