rule TTP_XOR_MULT_DOSStub_3811 {
  strings:
    $key_3811 = { 6c 79 [2] 18 61 [2] 5f 63 [2] 18 72 [2] 56 7e [2] 5a 74 [2] 4d 7f [2] 56 31 [2] 6b }

  condition:
    any of them
}