rule TTP_XOR_MULT_DOSStub_2043 {
  strings:
    $key_2043 = { 74 2b [2] 00 33 [2] 47 31 [2] 00 20 [2] 4e 2c [2] 42 26 [2] 55 2d [2] 4e 63 [2] 73 }

  condition:
    any of them
}