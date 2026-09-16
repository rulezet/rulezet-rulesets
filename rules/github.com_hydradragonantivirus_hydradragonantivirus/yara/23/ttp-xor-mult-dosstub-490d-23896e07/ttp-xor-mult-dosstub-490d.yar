rule TTP_XOR_MULT_DOSStub_490d {
  strings:
    $key_490d = { 1d 65 [2] 69 7d [2] 2e 7f [2] 69 6e [2] 27 62 [2] 2b 68 [2] 3c 63 [2] 27 2d [2] 1a }

  condition:
    any of them
}