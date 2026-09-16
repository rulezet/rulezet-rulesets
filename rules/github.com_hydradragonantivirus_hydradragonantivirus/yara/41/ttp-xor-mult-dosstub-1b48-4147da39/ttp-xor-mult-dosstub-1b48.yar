rule TTP_XOR_MULT_DOSStub_1b48 {
  strings:
    $key_1b48 = { 4f 20 [2] 3b 38 [2] 7c 3a [2] 3b 2b [2] 75 27 [2] 79 2d [2] 6e 26 [2] 75 68 [2] 48 }

  condition:
    any of them
}