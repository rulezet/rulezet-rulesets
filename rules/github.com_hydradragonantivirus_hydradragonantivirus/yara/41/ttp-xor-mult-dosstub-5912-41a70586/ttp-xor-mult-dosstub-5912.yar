rule TTP_XOR_MULT_DOSStub_5912 {
  strings:
    $key_5912 = { 0d 7a [2] 79 62 [2] 3e 60 [2] 79 71 [2] 37 7d [2] 3b 77 [2] 2c 7c [2] 37 32 [2] 0a }

  condition:
    any of them
}