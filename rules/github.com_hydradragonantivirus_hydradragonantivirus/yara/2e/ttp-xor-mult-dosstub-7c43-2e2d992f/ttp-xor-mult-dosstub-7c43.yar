rule TTP_XOR_MULT_DOSStub_7c43 {
  strings:
    $key_7c43 = { 28 2b [2] 5c 33 [2] 1b 31 [2] 5c 20 [2] 12 2c [2] 1e 26 [2] 09 2d [2] 12 63 [2] 2f }

  condition:
    any of them
}