rule TTP_XOR_MULT_DOSStub_7015 {
  strings:
    $key_7015 = { 24 7d [2] 50 65 [2] 17 67 [2] 50 76 [2] 1e 7a [2] 12 70 [2] 05 7b [2] 1e 35 [2] 23 }

  condition:
    any of them
}