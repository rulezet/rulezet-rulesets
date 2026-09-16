rule TTP_XOR_MULT_DOSStub_492b {
  strings:
    $key_492b = { 1d 43 [2] 69 5b [2] 2e 59 [2] 69 48 [2] 27 44 [2] 2b 4e [2] 3c 45 [2] 27 0b [2] 1a }

  condition:
    any of them
}