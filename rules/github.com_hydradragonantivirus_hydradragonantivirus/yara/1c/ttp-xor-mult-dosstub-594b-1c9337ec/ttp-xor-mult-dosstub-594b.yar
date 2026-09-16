rule TTP_XOR_MULT_DOSStub_594b {
  strings:
    $key_594b = { 0d 23 [2] 79 3b [2] 3e 39 [2] 79 28 [2] 37 24 [2] 3b 2e [2] 2c 25 [2] 37 6b [2] 0a }

  condition:
    any of them
}