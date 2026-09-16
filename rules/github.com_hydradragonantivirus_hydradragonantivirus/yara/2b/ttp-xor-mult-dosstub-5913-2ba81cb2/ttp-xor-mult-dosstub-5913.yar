rule TTP_XOR_MULT_DOSStub_5913 {
  strings:
    $key_5913 = { 0d 7b [2] 79 63 [2] 3e 61 [2] 79 70 [2] 37 7c [2] 3b 76 [2] 2c 7d [2] 37 33 [2] 0a }

  condition:
    any of them
}