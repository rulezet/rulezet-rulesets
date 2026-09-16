rule TTP_XOR_MULT_DOSStub_6373 {
  strings:
    $key_6373 = { 37 1b [2] 43 03 [2] 04 01 [2] 43 10 [2] 0d 1c [2] 01 16 [2] 16 1d [2] 0d 53 [2] 30 }

  condition:
    any of them
}