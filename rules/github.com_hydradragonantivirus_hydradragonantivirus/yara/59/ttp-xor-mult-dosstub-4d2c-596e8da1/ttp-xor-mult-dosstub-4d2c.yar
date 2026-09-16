rule TTP_XOR_MULT_DOSStub_4d2c {
  strings:
    $key_4d2c = { 19 44 [2] 6d 5c [2] 2a 5e [2] 6d 4f [2] 23 43 [2] 2f 49 [2] 38 42 [2] 23 0c [2] 1e }

  condition:
    any of them
}