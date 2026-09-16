rule TTP_XOR_MULT_DOSStub_4c5c {
  strings:
    $key_4c5c = { 18 34 [2] 6c 2c [2] 2b 2e [2] 6c 3f [2] 22 33 [2] 2e 39 [2] 39 32 [2] 22 7c [2] 1f }

  condition:
    any of them
}