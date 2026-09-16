rule TTP_XOR_MULT_DOSStub_3043 {
  strings:
    $key_3043 = { 64 2b [2] 10 33 [2] 57 31 [2] 10 20 [2] 5e 2c [2] 52 26 [2] 45 2d [2] 5e 63 [2] 63 }

  condition:
    any of them
}