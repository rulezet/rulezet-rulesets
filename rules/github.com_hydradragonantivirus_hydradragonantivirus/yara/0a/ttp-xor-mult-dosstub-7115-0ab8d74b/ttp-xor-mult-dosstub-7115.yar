rule TTP_XOR_MULT_DOSStub_7115 {
  strings:
    $key_7115 = { 25 7d [2] 51 65 [2] 16 67 [2] 51 76 [2] 1f 7a [2] 13 70 [2] 04 7b [2] 1f 35 [2] 22 }

  condition:
    any of them
}