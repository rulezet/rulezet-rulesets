rule TTP_XOR_MULT_DOSStub_2e44 {
  strings:
    $key_2e44 = { 7a 2c [2] 0e 34 [2] 49 36 [2] 0e 27 [2] 40 2b [2] 4c 21 [2] 5b 2a [2] 40 64 [2] 7d }

  condition:
    any of them
}