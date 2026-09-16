rule TTP_XOR_MULT_DOSStub_7a5c {
  strings:
    $key_7a5c = { 2e 34 [2] 5a 2c [2] 1d 2e [2] 5a 3f [2] 14 33 [2] 18 39 [2] 0f 32 [2] 14 7c [2] 29 }

  condition:
    any of them
}