rule TTP_XOR_MULT_DOSStub_49e8 {
  strings:
    $key_49e8 = { 1d 80 [2] 69 98 [2] 2e 9a [2] 69 8b [2] 27 87 [2] 2b 8d [2] 3c 86 [2] 27 c8 [2] 1a }

  condition:
    any of them
}