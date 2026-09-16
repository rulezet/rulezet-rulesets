rule TTP_XOR_MULT_DOSStub_2d73 {
  strings:
    $key_2d73 = { 79 1b [2] 0d 03 [2] 4a 01 [2] 0d 10 [2] 43 1c [2] 4f 16 [2] 58 1d [2] 43 53 [2] 7e }

  condition:
    any of them
}