rule TTP_XOR_MULT_DOSStub_2d45 {
  strings:
    $key_2d45 = { 79 2d [2] 0d 35 [2] 4a 37 [2] 0d 26 [2] 43 2a [2] 4f 20 [2] 58 2b [2] 43 65 [2] 7e }

  condition:
    any of them
}