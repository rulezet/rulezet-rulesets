rule TTP_XOR_MULT_DOSStub_3e5c {
  strings:
    $key_3e5c = { 6a 34 [2] 1e 2c [2] 59 2e [2] 1e 3f [2] 50 33 [2] 5c 39 [2] 4b 32 [2] 50 7c [2] 6d }

  condition:
    any of them
}