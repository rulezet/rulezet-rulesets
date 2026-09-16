rule TTP_XOR_MULT_DOSStub_35f5 {
  strings:
    $key_35f5 = { 61 9d [2] 15 85 [2] 52 87 [2] 15 96 [2] 5b 9a [2] 57 90 [2] 40 9b [2] 5b d5 [2] 66 }

  condition:
    any of them
}