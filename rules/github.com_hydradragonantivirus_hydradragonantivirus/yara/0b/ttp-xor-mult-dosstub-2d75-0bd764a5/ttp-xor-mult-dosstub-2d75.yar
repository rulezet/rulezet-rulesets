rule TTP_XOR_MULT_DOSStub_2d75 {
  strings:
    $key_2d75 = { 79 1d [2] 0d 05 [2] 4a 07 [2] 0d 16 [2] 43 1a [2] 4f 10 [2] 58 1b [2] 43 55 [2] 7e }

  condition:
    any of them
}