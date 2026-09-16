rule TTP_XOR_MULT_DOSStub_2d48 {
  strings:
    $key_2d48 = { 79 20 [2] 0d 38 [2] 4a 3a [2] 0d 2b [2] 43 27 [2] 4f 2d [2] 58 26 [2] 43 68 [2] 7e }

  condition:
    any of them
}