rule TTP_XOR_MULT_DOSStub_7b48 {
  strings:
    $key_7b48 = { 2f 20 [2] 5b 38 [2] 1c 3a [2] 5b 2b [2] 15 27 [2] 19 2d [2] 0e 26 [2] 15 68 [2] 28 }

  condition:
    any of them
}