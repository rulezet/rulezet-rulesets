rule TTP_XOR_MULT_DOSStub_27f5 {
  strings:
    $key_27f5 = { 73 9d [2] 07 85 [2] 40 87 [2] 07 96 [2] 49 9a [2] 45 90 [2] 52 9b [2] 49 d5 [2] 74 }

  condition:
    any of them
}