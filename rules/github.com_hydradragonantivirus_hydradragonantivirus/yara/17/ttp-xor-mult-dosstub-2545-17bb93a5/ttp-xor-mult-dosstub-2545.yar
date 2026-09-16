rule TTP_XOR_MULT_DOSStub_2545 {
  strings:
    $key_2545 = { 71 2d [2] 05 35 [2] 42 37 [2] 05 26 [2] 4b 2a [2] 47 20 [2] 50 2b [2] 4b 65 [2] 76 }

  condition:
    any of them
}