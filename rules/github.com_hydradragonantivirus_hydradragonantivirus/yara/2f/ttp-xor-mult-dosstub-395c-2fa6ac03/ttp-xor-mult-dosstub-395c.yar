rule TTP_XOR_MULT_DOSStub_395c {
  strings:
    $key_395c = { 6d 34 [2] 19 2c [2] 5e 2e [2] 19 3f [2] 57 33 [2] 5b 39 [2] 4c 32 [2] 57 7c [2] 6a }

  condition:
    any of them
}