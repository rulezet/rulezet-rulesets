rule TTP_XOR_MULT_DOSStub_7143 {
  strings:
    $key_7143 = { 25 2b [2] 51 33 [2] 16 31 [2] 51 20 [2] 1f 2c [2] 13 26 [2] 04 2d [2] 1f 63 [2] 22 }

  condition:
    any of them
}