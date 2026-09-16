rule TTP_XOR_MULT_DOSStub_493b {
  strings:
    $key_493b = { 1d 53 [2] 69 4b [2] 2e 49 [2] 69 58 [2] 27 54 [2] 2b 5e [2] 3c 55 [2] 27 1b [2] 1a }

  condition:
    any of them
}