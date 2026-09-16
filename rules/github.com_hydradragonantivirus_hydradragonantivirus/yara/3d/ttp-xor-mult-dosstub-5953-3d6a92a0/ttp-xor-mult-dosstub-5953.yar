rule TTP_XOR_MULT_DOSStub_5953 {
  strings:
    $key_5953 = { 0d 3b [2] 79 23 [2] 3e 21 [2] 79 30 [2] 37 3c [2] 3b 36 [2] 2c 3d [2] 37 73 [2] 0a }

  condition:
    any of them
}