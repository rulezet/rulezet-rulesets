rule TTP_XOR_MULT_DOSStub_5e5c {
  strings:
    $key_5e5c = { 0a 34 [2] 7e 2c [2] 39 2e [2] 7e 3f [2] 30 33 [2] 3c 39 [2] 2b 32 [2] 30 7c [2] 0d }

  condition:
    any of them
}