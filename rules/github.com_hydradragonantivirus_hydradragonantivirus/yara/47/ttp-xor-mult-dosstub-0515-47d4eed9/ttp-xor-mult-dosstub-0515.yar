rule TTP_XOR_MULT_DOSStub_0515 {
  strings:
    $key_0515 = { 51 7d [2] 25 65 [2] 62 67 [2] 25 76 [2] 6b 7a [2] 67 70 [2] 70 7b [2] 6b 35 [2] 56 }

  condition:
    any of them
}