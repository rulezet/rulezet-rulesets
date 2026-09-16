rule TTP_XOR_MULT_DOSStub_4473 {
  strings:
    $key_4473 = { 10 1b [2] 64 03 [2] 23 01 [2] 64 10 [2] 2a 1c [2] 26 16 [2] 31 1d [2] 2a 53 [2] 17 }

  condition:
    any of them
}