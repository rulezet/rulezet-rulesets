rule TTP_XOR_MULT_DOSStub_5e42 {
  strings:
    $key_5e42 = { 0a 2a [2] 7e 32 [2] 39 30 [2] 7e 21 [2] 30 2d [2] 3c 27 [2] 2b 2c [2] 30 62 [2] 0d }

  condition:
    any of them
}