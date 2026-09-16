rule TTP_XOR_MULT_DOSStub_7df5 {
  strings:
    $key_7df5 = { 29 9d [2] 5d 85 [2] 1a 87 [2] 5d 96 [2] 13 9a [2] 1f 90 [2] 08 9b [2] 13 d5 [2] 2e }

  condition:
    any of them
}