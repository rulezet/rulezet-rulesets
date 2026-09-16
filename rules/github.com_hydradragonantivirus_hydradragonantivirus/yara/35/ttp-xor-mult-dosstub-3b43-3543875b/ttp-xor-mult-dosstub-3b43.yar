rule TTP_XOR_MULT_DOSStub_3b43 {
  strings:
    $key_3b43 = { 6f 2b [2] 1b 33 [2] 5c 31 [2] 1b 20 [2] 55 2c [2] 59 26 [2] 4e 2d [2] 55 63 [2] 68 }

  condition:
    any of them
}