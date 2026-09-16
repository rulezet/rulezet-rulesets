rule TTP_XOR_MULT_DOSStub_6043 {
  strings:
    $key_6043 = { 34 2b [2] 40 33 [2] 07 31 [2] 40 20 [2] 0e 2c [2] 02 26 [2] 15 2d [2] 0e 63 [2] 33 }

  condition:
    any of them
}