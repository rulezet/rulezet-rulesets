rule TTP_XOR_MULT_DOSStub_2e42 {
  strings:
    $key_2e42 = { 7a 2a [2] 0e 32 [2] 49 30 [2] 0e 21 [2] 40 2d [2] 4c 27 [2] 5b 2c [2] 40 62 [2] 7d }

  condition:
    any of them
}