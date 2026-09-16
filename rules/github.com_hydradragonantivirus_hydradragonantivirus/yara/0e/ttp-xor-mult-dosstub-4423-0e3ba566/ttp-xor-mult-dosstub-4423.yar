rule TTP_XOR_MULT_DOSStub_4423 {
  strings:
    $key_4423 = { 10 4b [2] 64 53 [2] 23 51 [2] 64 40 [2] 2a 4c [2] 26 46 [2] 31 4d [2] 2a 03 [2] 17 }

  condition:
    any of them
}