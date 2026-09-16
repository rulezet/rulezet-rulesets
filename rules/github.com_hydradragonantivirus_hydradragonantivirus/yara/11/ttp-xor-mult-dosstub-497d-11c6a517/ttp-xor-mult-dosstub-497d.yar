rule TTP_XOR_MULT_DOSStub_497d {
  strings:
    $key_497d = { 1d 15 [2] 69 0d [2] 2e 0f [2] 69 1e [2] 27 12 [2] 2b 18 [2] 3c 13 [2] 27 5d [2] 1a }

  condition:
    any of them
}