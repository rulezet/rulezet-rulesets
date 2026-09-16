rule TTP_XOR_MULT_DOSStub_4b43 {
  strings:
    $key_4b43 = { 1f 2b [2] 6b 33 [2] 2c 31 [2] 6b 20 [2] 25 2c [2] 29 26 [2] 3e 2d [2] 25 63 [2] 18 }

  condition:
    any of them
}