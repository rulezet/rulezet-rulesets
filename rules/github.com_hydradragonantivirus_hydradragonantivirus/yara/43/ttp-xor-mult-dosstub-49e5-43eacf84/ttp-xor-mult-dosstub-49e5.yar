rule TTP_XOR_MULT_DOSStub_49e5 {
  strings:
    $key_49e5 = { 1d 8d [2] 69 95 [2] 2e 97 [2] 69 86 [2] 27 8a [2] 2b 80 [2] 3c 8b [2] 27 c5 [2] 1a }

  condition:
    any of them
}