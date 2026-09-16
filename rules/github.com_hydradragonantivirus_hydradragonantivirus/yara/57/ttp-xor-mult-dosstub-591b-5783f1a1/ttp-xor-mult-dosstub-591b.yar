rule TTP_XOR_MULT_DOSStub_591b {
  strings:
    $key_591b = { 0d 73 [2] 79 6b [2] 3e 69 [2] 79 78 [2] 37 74 [2] 3b 7e [2] 2c 75 [2] 37 3b [2] 0a }

  condition:
    any of them
}