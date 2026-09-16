rule TTP_XOR_MULT_DOSStub_3378 {
  strings:
    $key_3378 = { 67 10 [2] 13 08 [2] 54 0a [2] 13 1b [2] 5d 17 [2] 51 1d [2] 46 16 [2] 5d 58 [2] 60 }

  condition:
    any of them
}