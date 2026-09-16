rule TTP_XOR_MULT_DOSStub_1143 {
  strings:
    $key_1143 = { 45 2b [2] 31 33 [2] 76 31 [2] 31 20 [2] 7f 2c [2] 73 26 [2] 64 2d [2] 7f 63 [2] 42 }

  condition:
    any of them
}