rule TTP_XOR_MULT_DOSStub_5273 {
  strings:
    $key_5273 = { 06 1b [2] 72 03 [2] 35 01 [2] 72 10 [2] 3c 1c [2] 30 16 [2] 27 1d [2] 3c 53 [2] 01 }

  condition:
    any of them
}