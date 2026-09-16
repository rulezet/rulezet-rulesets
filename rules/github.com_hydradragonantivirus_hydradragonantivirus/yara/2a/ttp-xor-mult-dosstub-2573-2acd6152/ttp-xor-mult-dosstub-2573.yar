rule TTP_XOR_MULT_DOSStub_2573 {
  strings:
    $key_2573 = { 71 1b [2] 05 03 [2] 42 01 [2] 05 10 [2] 4b 1c [2] 47 16 [2] 50 1d [2] 4b 53 [2] 76 }

  condition:
    any of them
}