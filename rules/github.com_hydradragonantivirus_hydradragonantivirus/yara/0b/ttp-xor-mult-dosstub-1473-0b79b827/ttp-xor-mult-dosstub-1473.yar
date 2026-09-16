rule TTP_XOR_MULT_DOSStub_1473 {
  strings:
    $key_1473 = { 40 1b [2] 34 03 [2] 73 01 [2] 34 10 [2] 7a 1c [2] 76 16 [2] 61 1d [2] 7a 53 [2] 47 }

  condition:
    any of them
}