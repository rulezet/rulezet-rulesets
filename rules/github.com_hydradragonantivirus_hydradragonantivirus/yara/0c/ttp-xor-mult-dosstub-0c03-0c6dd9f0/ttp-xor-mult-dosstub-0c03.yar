rule TTP_XOR_MULT_DOSStub_0c03 {
  strings:
    $key_0c03 = { 58 6b [2] 2c 73 [2] 6b 71 [2] 2c 60 [2] 62 6c [2] 6e 66 [2] 79 6d [2] 62 23 [2] 5f }

  condition:
    any of them
}