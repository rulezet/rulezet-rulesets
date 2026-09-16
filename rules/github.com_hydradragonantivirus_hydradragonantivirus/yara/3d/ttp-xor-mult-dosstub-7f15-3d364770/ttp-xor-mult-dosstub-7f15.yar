rule TTP_XOR_MULT_DOSStub_7f15 {
  strings:
    $key_7f15 = { 2b 7d [2] 5f 65 [2] 18 67 [2] 5f 76 [2] 11 7a [2] 1d 70 [2] 0a 7b [2] 11 35 [2] 2c }

  condition:
    any of them
}