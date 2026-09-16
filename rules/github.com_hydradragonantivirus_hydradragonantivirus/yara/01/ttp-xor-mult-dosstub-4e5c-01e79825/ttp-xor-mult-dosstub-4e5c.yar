rule TTP_XOR_MULT_DOSStub_4e5c {
  strings:
    $key_4e5c = { 1a 34 [2] 6e 2c [2] 29 2e [2] 6e 3f [2] 20 33 [2] 2c 39 [2] 3b 32 [2] 20 7c [2] 1d }

  condition:
    any of them
}