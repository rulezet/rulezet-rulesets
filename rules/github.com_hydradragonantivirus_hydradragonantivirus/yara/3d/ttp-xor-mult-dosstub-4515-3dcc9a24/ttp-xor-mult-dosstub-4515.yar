rule TTP_XOR_MULT_DOSStub_4515 {
  strings:
    $key_4515 = { 11 7d [2] 65 65 [2] 22 67 [2] 65 76 [2] 2b 7a [2] 27 70 [2] 30 7b [2] 2b 35 [2] 16 }

  condition:
    any of them
}