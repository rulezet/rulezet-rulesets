rule TTP_XOR_MULT_DOSStub_4c2c {
  strings:
    $key_4c2c = { 18 44 [2] 6c 5c [2] 2b 5e [2] 6c 4f [2] 22 43 [2] 2e 49 [2] 39 42 [2] 22 0c [2] 1f }

  condition:
    any of them
}