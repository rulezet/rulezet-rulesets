rule TTP_XOR_MULT_DOSStub_5e2c {
  strings:
    $key_5e2c = { 0a 44 [2] 7e 5c [2] 39 5e [2] 7e 4f [2] 30 43 [2] 3c 49 [2] 2b 42 [2] 30 0c [2] 0d }

  condition:
    any of them
}