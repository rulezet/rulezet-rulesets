rule TTP_XOR_MULT_DOSStub_493d {
  strings:
    $key_493d = { 1d 55 [2] 69 4d [2] 2e 4f [2] 69 5e [2] 27 52 [2] 2b 58 [2] 3c 53 [2] 27 1d [2] 1a }

  condition:
    any of them
}