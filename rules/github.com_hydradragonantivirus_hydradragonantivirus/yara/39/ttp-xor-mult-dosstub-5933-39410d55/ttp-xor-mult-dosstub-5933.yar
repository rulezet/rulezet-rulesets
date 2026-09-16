rule TTP_XOR_MULT_DOSStub_5933 {
  strings:
    $key_5933 = { 0d 5b [2] 79 43 [2] 3e 41 [2] 79 50 [2] 37 5c [2] 3b 56 [2] 2c 5d [2] 37 13 [2] 0a }

  condition:
    any of them
}