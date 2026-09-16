rule TTP_XOR_MULT_DOSStub_4573 {
  strings:
    $key_4573 = { 11 1b [2] 65 03 [2] 22 01 [2] 65 10 [2] 2b 1c [2] 27 16 [2] 30 1d [2] 2b 53 [2] 16 }

  condition:
    any of them
}