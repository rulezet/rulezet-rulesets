rule TTP_XOR_MULT_DOSStub_25f5 {
  strings:
    $key_25f5 = { 71 9d [2] 05 85 [2] 42 87 [2] 05 96 [2] 4b 9a [2] 47 90 [2] 50 9b [2] 4b d5 [2] 76 }

  condition:
    any of them
}