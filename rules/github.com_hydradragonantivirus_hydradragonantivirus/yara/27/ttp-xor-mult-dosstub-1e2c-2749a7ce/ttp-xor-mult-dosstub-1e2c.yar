rule TTP_XOR_MULT_DOSStub_1e2c {
  strings:
    $key_1e2c = { 4a 44 [2] 3e 5c [2] 79 5e [2] 3e 4f [2] 70 43 [2] 7c 49 [2] 6b 42 [2] 70 0c [2] 4d }

  condition:
    any of them
}