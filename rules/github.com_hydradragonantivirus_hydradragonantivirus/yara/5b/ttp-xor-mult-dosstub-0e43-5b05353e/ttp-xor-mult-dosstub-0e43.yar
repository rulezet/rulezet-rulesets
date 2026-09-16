rule TTP_XOR_MULT_DOSStub_0e43 {
  strings:
    $key_0e43 = { 5a 2b [2] 2e 33 [2] 69 31 [2] 2e 20 [2] 60 2c [2] 6c 26 [2] 7b 2d [2] 60 63 [2] 5d }

  condition:
    any of them
}