rule TTP_XOR_MULT_DOSStub_7d2c {
  strings:
    $key_7d2c = { 29 44 [2] 5d 5c [2] 1a 5e [2] 5d 4f [2] 13 43 [2] 1f 49 [2] 08 42 [2] 13 0c [2] 2e }

  condition:
    any of them
}