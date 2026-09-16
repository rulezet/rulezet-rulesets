rule TTP_XOR_MULT_DOSStub_7e5c {
  strings:
    $key_7e5c = { 2a 34 [2] 5e 2c [2] 19 2e [2] 5e 3f [2] 10 33 [2] 1c 39 [2] 0b 32 [2] 10 7c [2] 2d }

  condition:
    any of them
}