rule TTP_XOR_MULT_DOSStub_56f5 {
  strings:
    $key_56f5 = { 02 9d [2] 76 85 [2] 31 87 [2] 76 96 [2] 38 9a [2] 34 90 [2] 23 9b [2] 38 d5 [2] 05 }

  condition:
    any of them
}