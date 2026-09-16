rule TTP_XOR_MULT_DOSStub_2548 {
  strings:
    $key_2548 = { 71 20 [2] 05 38 [2] 42 3a [2] 05 2b [2] 4b 27 [2] 47 2d [2] 50 26 [2] 4b 68 [2] 76 }

  condition:
    any of them
}