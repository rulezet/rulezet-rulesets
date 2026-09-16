rule TTP_XOR_MULT_DOSStub_3115 {
  strings:
    $key_3115 = { 65 7d [2] 11 65 [2] 56 67 [2] 11 76 [2] 5f 7a [2] 53 70 [2] 44 7b [2] 5f 35 [2] 62 }

  condition:
    any of them
}