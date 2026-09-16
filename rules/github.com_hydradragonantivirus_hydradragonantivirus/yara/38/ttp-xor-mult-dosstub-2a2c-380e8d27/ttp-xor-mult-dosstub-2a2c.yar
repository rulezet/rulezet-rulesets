rule TTP_XOR_MULT_DOSStub_2a2c {
  strings:
    $key_2a2c = { 7e 44 [2] 0a 5c [2] 4d 5e [2] 0a 4f [2] 44 43 [2] 48 49 [2] 5f 42 [2] 44 0c [2] 79 }

  condition:
    any of them
}