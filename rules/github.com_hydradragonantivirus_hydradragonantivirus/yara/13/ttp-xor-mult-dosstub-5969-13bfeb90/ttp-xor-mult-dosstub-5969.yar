rule TTP_XOR_MULT_DOSStub_5969 {
  strings:
    $key_5969 = { 0d 01 [2] 79 19 [2] 3e 1b [2] 79 0a [2] 37 06 [2] 3b 0c [2] 2c 07 [2] 37 49 [2] 0a }

  condition:
    any of them
}