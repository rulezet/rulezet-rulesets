rule TTP_XOR_MULT_DOSStub_7e2c {
  strings:
    $key_7e2c = { 2a 44 [2] 5e 5c [2] 19 5e [2] 5e 4f [2] 10 43 [2] 1c 49 [2] 0b 42 [2] 10 0c [2] 2d }

  condition:
    any of them
}