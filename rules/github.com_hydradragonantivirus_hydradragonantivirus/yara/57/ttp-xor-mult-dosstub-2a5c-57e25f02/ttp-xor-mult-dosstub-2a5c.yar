rule TTP_XOR_MULT_DOSStub_2a5c {
  strings:
    $key_2a5c = { 7e 34 [2] 0a 2c [2] 4d 2e [2] 0a 3f [2] 44 33 [2] 48 39 [2] 5f 32 [2] 44 7c [2] 79 }

  condition:
    any of them
}