rule TTP_XOR_MULT_DOSStub_797b {
  strings:
    $key_797b = { 2d 13 [2] 59 0b [2] 1e 09 [2] 59 18 [2] 17 14 [2] 1b 1e [2] 0c 15 [2] 17 5b [2] 2a }

  condition:
    any of them
}