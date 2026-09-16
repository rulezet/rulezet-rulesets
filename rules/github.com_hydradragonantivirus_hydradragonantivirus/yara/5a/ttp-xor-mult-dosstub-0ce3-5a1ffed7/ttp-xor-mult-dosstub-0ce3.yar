rule TTP_XOR_MULT_DOSStub_0ce3 {
  strings:
    $key_0ce3 = { 58 8b [2] 2c 93 [2] 6b 91 [2] 2c 80 [2] 62 8c [2] 6e 86 [2] 79 8d [2] 62 c3 [2] 5f }

  condition:
    any of them
}