rule TTP_XOR_MULT_DOSStub_5569 {
  strings:
    $key_5569 = { 01 01 [2] 75 19 [2] 32 1b [2] 75 0a [2] 3b 06 [2] 37 0c [2] 20 07 [2] 3b 49 [2] 06 }

  condition:
    any of them
}