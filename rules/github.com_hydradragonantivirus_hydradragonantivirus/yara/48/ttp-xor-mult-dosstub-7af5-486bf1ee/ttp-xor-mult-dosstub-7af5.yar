rule TTP_XOR_MULT_DOSStub_7af5 {
  strings:
    $key_7af5 = { 2e 9d [2] 5a 85 [2] 1d 87 [2] 5a 96 [2] 14 9a [2] 18 90 [2] 0f 9b [2] 14 d5 [2] 29 }

  condition:
    any of them
}