rule TTP_XOR_MULT_DOSStub_2d35 {
  strings:
    $key_2d35 = { 79 5d [2] 0d 45 [2] 4a 47 [2] 0d 56 [2] 43 5a [2] 4f 50 [2] 58 5b [2] 43 15 [2] 7e }

  condition:
    any of them
}