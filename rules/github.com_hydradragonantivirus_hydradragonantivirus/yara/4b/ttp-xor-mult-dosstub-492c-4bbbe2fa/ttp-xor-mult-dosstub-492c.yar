rule TTP_XOR_MULT_DOSStub_492c {
  strings:
    $key_492c = { 1d 44 [2] 69 5c [2] 2e 5e [2] 69 4f [2] 27 43 [2] 2b 49 [2] 3c 42 [2] 27 0c [2] 1a }

  condition:
    any of them
}