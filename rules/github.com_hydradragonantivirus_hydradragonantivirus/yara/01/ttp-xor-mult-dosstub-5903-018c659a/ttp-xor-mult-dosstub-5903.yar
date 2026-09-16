rule TTP_XOR_MULT_DOSStub_5903 {
  strings:
    $key_5903 = { 0d 6b [2] 79 73 [2] 3e 71 [2] 79 60 [2] 37 6c [2] 3b 66 [2] 2c 6d [2] 37 23 [2] 0a }

  condition:
    any of them
}