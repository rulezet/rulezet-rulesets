rule TTP_XOR_MULT_DOSStub_0e5c {
  strings:
    $key_0e5c = { 5a 34 [2] 2e 2c [2] 69 2e [2] 2e 3f [2] 60 33 [2] 6c 39 [2] 7b 32 [2] 60 7c [2] 5d }

  condition:
    any of them
}