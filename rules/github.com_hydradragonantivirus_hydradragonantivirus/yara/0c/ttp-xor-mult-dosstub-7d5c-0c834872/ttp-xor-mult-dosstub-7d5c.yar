rule TTP_XOR_MULT_DOSStub_7d5c {
  strings:
    $key_7d5c = { 29 34 [2] 5d 2c [2] 1a 2e [2] 5d 3f [2] 13 33 [2] 1f 39 [2] 08 32 [2] 13 7c [2] 2e }

  condition:
    any of them
}