rule TTP_XOR_MULT_DOSStub_5914 {
  strings:
    $key_5914 = { 0d 7c [2] 79 64 [2] 3e 66 [2] 79 77 [2] 37 7b [2] 3b 71 [2] 2c 7a [2] 37 34 [2] 0a }

  condition:
    any of them
}